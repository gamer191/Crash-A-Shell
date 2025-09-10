import os
import platform
import struct
import sys
from contextlib import ExitStack, contextmanager
from ctypes import (CDLL, CFUNCTYPE, POINTER, Structure, c_bool, c_byte,
                    c_char, c_char_p, c_double, c_float, c_int, c_int8,
                    c_int16, c_int32, c_int64, c_long, c_longdouble,
                    c_longlong, c_short, c_size_t, c_ssize_t, c_ubyte, c_uint,
                    c_uint8, c_uint16, c_uint32, c_uint64, c_ulong,
                    c_ulonglong, c_ushort, c_void_p, c_wchar, c_wchar_p, cast,
                    pointer, sizeof)
from ctypes.util import find_library
from functools import wraps
from stat import S_ISREG
from typing import Any, Callable, Generator, Optional, TypeVar, Union, overload
from typing import cast as py_typecast

T = TypeVar('T')


class _DefaultTag:
    ...


@overload
def debug_log(msg: T) -> T: ...
@overload
def debug_log(msg, *, ret: T) -> T: ...


def debug_log(msg, *, ret: Any = _DefaultTag):
    if S_ISREG(os.fstat(1).st_mode):
        os.fsync(1)
    if ret is _DefaultTag:
        ret = msg
    return ret


def setup_signature(c_fn, restype: Optional[type] = None, *argtypes: type):
    c_fn.argtypes = argtypes
    c_fn.restype = restype
    return c_fn


def cfn_at(addr: int, restype: Optional[type] = None, *argtypes: type) -> Callable:
    return CFUNCTYPE(restype, *argtypes)(addr)


def as_fnptr(cb: Callable, restype: Optional[type] = None, *argtypes: type) -> c_void_p:
    return cast(CFUNCTYPE(restype, *argtypes)(cb), c_void_p)


class DLError(OSError):
    UNKNOWN_ERROR = b'<unknown error>'

    def __init__(self, fname: bytes, arg: str, err: Optional[bytes]) -> None:
        self.fname = fname
        self.err = err
        self.arg = arg

    def __str__(self) -> str:
        arg = ''
        if self.arg:
            arg = f' {self.arg}'
        errm = self.err or DLError.UNKNOWN_ERROR
        return f'Failed to {self.fname.decode()}{arg}: {errm.decode()}'

    def __repr__(self) -> str:
        return f'DLError(fname={self.fname!r}, arg={self.arg!r}, err={self.err!r})'

    @staticmethod
    def handle(ret: Optional[int], fname: bytes, arg: str, err: Optional[bytes]) -> int:
        if not ret:
            raise DLError(fname, arg, err)
        return ret

    @staticmethod
    def wrap(fn, fname: bytes, errfn: Callable[[], Optional[bytes]], *partial, success_handle):
        return wraps(fn)(lambda *args: success_handle(DLError.handle(fn(*partial, *args), fname, ''.join(map(str, args)), errfn())))


class NotNull_VoidP(c_void_p):
    def __init__(self, value: int):
        super().__init__(value)

    @property
    def value(self) -> int:
        return py_typecast(int, super().value)


DLSYM_FUNC = Callable[[bytes], NotNull_VoidP]


def dlsym_factory(ldl_openmode: int = os.RTLD_NOW):
    ldl = CDLL(find_library('dl'), mode=ldl_openmode)
    fn_dlopen = setup_signature(ldl.dlopen, c_void_p, c_char_p, c_int)
    fn_dlsym = setup_signature(ldl.dlsym, c_void_p, c_void_p, c_char_p)
    fn_dlclose = setup_signature(ldl.dlclose, c_int, c_void_p)
    fn_dlerror = setup_signature(ldl.dlerror, c_char_p)

    @contextmanager
    def dlsym_factory(path: bytes, mode: int = os.RTLD_LAZY) -> Generator[DLSYM_FUNC, None, None]:
        h_lib = DLError.handle(
            fn_dlopen(path, mode),
            b'dlopen', path.decode(), fn_dlerror())
        try:
            yield DLError.wrap(fn_dlsym, b'dlsym', fn_dlerror, c_void_p(h_lib), success_handle=lambda x: c_void_p((lambda x: debug_log(f'dlsym@{x}', ret=x))(x)))
        finally:
            DLError.handle(
                not fn_dlclose(h_lib),
                b'dlclose', path.decode(), fn_dlerror())
    return dlsym_factory


class objc_super(Structure):
    _fields_ = (
        ('receiver', c_void_p),
        ('super_class', c_void_p),
    )


Integral = Union[
        type[c_byte], type[c_ubyte], type[c_short], type[c_ushort], type[c_int], type[c_int8],
        type[c_int16], type[c_int32], type[c_int64], type[c_uint], type[c_uint8], type[c_uint16],
        type[c_uint32], type[c_uint64], type[c_long], type[c_ulong], type[c_longlong], type[c_ulonglong],
        type[c_size_t], type[c_ssize_t],]

class PyNeApple:
    __slots__ = (
        '_stack', 'dlsym_of_lib', '_fwks', '_init',
        '_objc', '_system',
        'p_NSConcreteMallocBlock',
        'class_addProtocol', 'class_addMethod', 'class_addIvar',
        'class_conformsToProtocol',
        'objc_getProtocol', 'objc_allocateClassPair', 'objc_registerClassPair',
        'objc_getClass', 'pobjc_msgSend', 'pobjc_msgSendSuper',
        'object_getClass', 'object_getInstanceVariable', 'object_setInstanceVariable',
        'sel_registerName',
    )

    @staticmethod
    def path_to_framework(fwk_name: str, use_findlib: bool = False) -> Optional[str]:
        if use_findlib:
            return find_library(fwk_name)
        return f'/System/Library/Frameworks/{fwk_name}.framework/{fwk_name}'

    def __init__(self):
        self._init = False

    def __enter__(self):
        self._stack = ExitStack()
        self.dlsym_of_lib = dlsym_factory()
        self._fwks: dict[str, DLSYM_FUNC] = {}
        self._init = True

        self._objc = self._stack.enter_context(self.dlsym_of_lib(b'/usr/lib/libobjc.A.dylib', os.RTLD_NOW))
        self._system = self._stack.enter_context(self.dlsym_of_lib(b'/usr/lib/libSystem.B.dylib', os.RTLD_LAZY))
        self.p_NSConcreteMallocBlock = self._system(b'_NSConcreteMallocBlock').value

        self.class_addProtocol = cfn_at(self._objc(b'class_addProtocol').value, c_byte, c_void_p, c_void_p)
        self.class_addMethod = cfn_at(self._objc(b'class_addMethod').value, c_byte, c_void_p, c_void_p, c_void_p, c_char_p)
        self.class_addIvar = cfn_at(self._objc(b'class_addIvar').value, c_byte, c_void_p, c_char_p, c_size_t, c_uint8, c_char_p)
        self.class_conformsToProtocol = cfn_at(self._objc(b'class_conformsToProtocol').value, c_byte, c_void_p, c_void_p)

        self.objc_getProtocol = cfn_at(self._objc(b'objc_getProtocol').value, c_void_p, c_char_p)
        self.objc_allocateClassPair = cfn_at(self._objc(b'objc_allocateClassPair').value, c_void_p, c_void_p, c_char_p, c_size_t)
        self.objc_registerClassPair = cfn_at(self._objc(b'objc_registerClassPair').value, None, c_void_p)
        self.objc_getClass = cfn_at(self._objc(b'objc_getClass').value, c_void_p, c_char_p)
        self.pobjc_msgSend = self._objc(b'objc_msgSend').value
        self.pobjc_msgSendSuper = self._objc(b'objc_msgSendSuper').value

        self.object_getClass = cfn_at(self._objc(b'object_getClass').value, c_void_p, c_void_p)
        self.object_getInstanceVariable = cfn_at(
            self._objc(b'object_getInstanceVariable').value, c_void_p,
            c_void_p, c_char_p, POINTER(c_void_p))
        self.object_setInstanceVariable = cfn_at(
            self._objc(b'object_setInstanceVariable').value, c_void_p,
            c_void_p, c_char_p, c_void_p)

        self.sel_registerName = cfn_at(self._objc(b'sel_registerName').value, c_void_p, c_char_p)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._stack.__exit__(exc_type, exc_value, traceback)

    def open_dylib(self, path: bytes, mode=os.RTLD_LAZY) -> DLSYM_FUNC:
        return self._stack.enter_context(self.dlsym_of_lib(path, mode=mode))

    def load_framework_from_path(self, fwk_name: str, fwk_path: Optional[str] = None, mode=os.RTLD_LAZY) -> DLSYM_FUNC:
        fwk_path = PyNeApple.path_to_framework(fwk_name)
        if fwk := self._fwks.get(fwk_name):
            return fwk
        ret = self._fwks[fwk_name] = self.open_dylib(fwk_path.encode(), mode)
        return ret

    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: type[c_bool], argtypes: tuple[type, ...], is_super: bool = False) -> bool: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: type[c_char], argtypes: tuple[type, ...], is_super: bool = False) -> bytes: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: type[c_wchar], argtypes: tuple[type, ...], is_super: bool = False) -> str: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: Integral, argtypes: tuple[type, ...], is_super: bool = False) -> int: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: type[c_char_p], argtypes: tuple[type, ...], is_super: bool = False) -> Union[bytes, None]: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: type[c_wchar_p], argtypes: tuple[type, ...], is_super: bool = False) -> Union[str, None]: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: type[c_void_p], argtypes: tuple[type, ...], is_super: bool = False) -> Union[int, None]: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: None = None, argtypes: tuple[type, ...], is_super: bool = False) -> None: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: type[c_bool], is_super: bool = False) -> bool: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: type[c_char], is_super: bool = False) -> bytes: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: type[c_wchar], is_super: bool = False) -> str: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: Integral, is_super: bool = False) -> int: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: type[c_char_p], is_super: bool = False) -> Union[bytes, None]: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: type[c_wchar_p], is_super: bool = False) -> Union[str, None]: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: type[c_void_p], is_super: bool = False) -> Union[int, None]: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: None = None, is_super: bool = False) -> None: ...

    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: Optional[type] = None, argtypes: tuple[type, ...] = (), is_super: bool = False):
        sel = c_void_p(self.sel_registerName(sel_name))
        if is_super:
            receiver = objc_super(receiver=obj, super_class=c_void_p(self.send_message(self.object_getClass(obj), b'superclass', restype=c_void_p)))
            cfn_at(self.pobjc_msgSendSuper, restype, objc_super, c_void_p, *argtypes)(receiver, sel, *args)
        return cfn_at(self.pobjc_msgSend, restype, c_void_p, c_void_p, *argtypes)(obj, sel, *args)

    def safe_new_object(self, cls: c_void_p, init_name: bytes = b'init', *args, argtypes: tuple[type, ...] = ()) -> NotNull_VoidP:
        obj = c_void_p(self.send_message(cls, b'alloc', restype=c_void_p))
        obj = c_void_p(self.send_message(obj, init_name, restype=c_void_p, *args, argtypes=argtypes))
        return NotNull_VoidP(obj.value)

    def safe_objc_getClass(self, name: bytes) -> NotNull_VoidP:
        Cls = c_void_p(self.objc_getClass(name))
        return NotNull_VoidP(Cls.value)


class DoubleDouble(Structure):
    _fields_ = (
        ('x', c_double),
        ('y', c_double),
    )


class CGRect(Structure):
    _fields_ = (
        ('orig', DoubleDouble),
        ('size', DoubleDouble),
    )


with PyNeApple() as pa:
    pa.load_framework_from_path('WebKit')
    pa.safe_new_object(
        pa.safe_objc_getClass(b'WKWebView'), b'initWithFrame:configuration:',
        CGRect(), pa.safe_new_object(c_void_p(pa.objc_getClass(b'WKWebViewConfiguration'))),
        argtypes=(CGRect, c_void_p))
