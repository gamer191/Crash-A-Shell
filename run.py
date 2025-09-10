import os
import platform
import struct
import sys
from contextlib import ExitStack, contextmanager
from ctypes import (CDLL, CFUNCTYPE, POINTER, Structure, byref, c_bool, c_byte,
                    c_char, c_char_p, c_double, c_float, c_int, c_int8,
                    c_int16, c_int32, c_int64, c_long, c_longdouble,
                    c_longlong, c_short, c_size_t, c_ssize_t, c_ubyte, c_uint,
                    c_uint8, c_uint16, c_uint32, c_uint64, c_ulong,
                    c_ulonglong, c_ushort, c_void_p, c_wchar, c_wchar_p, cast,
                    pointer, sizeof)
from ctypes.util import find_library
from functools import wraps
from stat import S_ISREG
from typing import Any, Callable, Generator, Optional, TypeVar, Union
from typing import cast as py_typecast
from typing import overload

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
    argss = ', '.join(str(t) for t in argtypes)
    return CFUNCTYPE(restype, *argtypes)(addr)


def as_fnptr(cb: Callable, restype: Optional[type] = None, *argtypes: type) -> c_void_p:
    argss = ', '.join(str(t) for t in argtypes)
    fnptr = cast(CFUNCTYPE(restype, *argtypes)(cb), c_void_p)
    return fnptr


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
    # void *dlopen(const char *file, int mode);
    fn_dlopen = setup_signature(ldl.dlopen, c_void_p, c_char_p, c_int)
    # void *dlsym(void *restrict handle, const char *restrict name);
    fn_dlsym = setup_signature(ldl.dlsym, c_void_p, c_void_p, c_char_p)
    # int dlclose(void *handle);
    fn_dlclose = setup_signature(ldl.dlclose, c_int, c_void_p)
    # char *dlerror(void);
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


class CRet:
    Boolean = type[c_bool]
    Py_Boolean = bool

    Char = type[c_char]
    Py_Char = bytes

    Str = type[c_wchar]
    Py_Str = str

    _IntegralBase = Union[
        type[c_byte], type[c_ubyte], type[c_short], type[c_ushort], type[c_int], type[c_int8],
        type[c_int16], type[c_int32], type[c_int64], type[c_uint], type[c_uint8], type[c_uint16],
        type[c_uint32], type[c_uint64], type[c_long], type[c_ulong], type[c_longlong], type[c_ulonglong],
        type[c_size_t], type[c_ssize_t],
    ]
    if sys.version_info >= (3, 12):
        from ctypes import c_time_t
        Integral = Union[_IntegralBase, type[c_time_t]]
    else:
        Integral = _IntegralBase
    Py_Integral = int

    CharSeq = type[c_char_p]
    Py_CharSeq = Union[bytes, None]

    StrSeq = type[c_wchar_p]
    Py_StrSeq = Union[str, None]

    PVoid = type[c_void_p]
    Py_PVoid = Union[int, None]

    Float = Union[type[c_float], type[c_double], type[c_longdouble]]
    Py_Float = float


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
        if platform.uname()[0] != 'Darwin':
            print('Warning: kernel is not Darwin, PyNeApple might not function correctly')
        self._init = False

    def __enter__(self):
        if self._init:
            raise RuntimeError('instance already initialized, please create a new instance')
        try:
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
        except Exception as e:
            if hasattr(self, '_stack'):
                self._stack.close()
            raise e

    def __exit__(self, exc_type, exc_value, traceback):
        return self._stack.__exit__(exc_type, exc_value, traceback)

    @property
    def dlsym_objc(self):
        return self._objc

    @property
    def dlsym_system(self):
        return self._system

    def open_dylib(self, path: bytes, mode=os.RTLD_LAZY) -> DLSYM_FUNC:
        return self._stack.enter_context(self.dlsym_of_lib(path, mode=mode))

    def load_framework_from_path(self, fwk_name: str, fwk_path: Optional[str] = None, mode=os.RTLD_LAZY) -> DLSYM_FUNC:
        if not fwk_path:
            fwk_path = PyNeApple.path_to_framework(fwk_name)
            if not fwk_path:
                raise ValueError(f'Could not find framework {fwk_name}, please provide a valid path')
        if fwk := self._fwks.get(fwk_name):
            return fwk
        ret = self._fwks[fwk_name] = self.open_dylib(fwk_path.encode(), mode)
        return ret

    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: CRet.Boolean, argtypes: tuple[type, ...], is_super: bool = False) -> CRet.Py_Boolean: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: CRet.Char, argtypes: tuple[type, ...], is_super: bool = False) -> CRet.Py_Char: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: CRet.Str, argtypes: tuple[type, ...], is_super: bool = False) -> CRet.Py_Str: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: CRet.Integral, argtypes: tuple[type, ...], is_super: bool = False) -> CRet.Py_Integral: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: CRet.CharSeq, argtypes: tuple[type, ...], is_super: bool = False) -> CRet.Py_CharSeq: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: CRet.StrSeq, argtypes: tuple[type, ...], is_super: bool = False) -> CRet.Py_StrSeq: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: CRet.PVoid, argtypes: tuple[type, ...], is_super: bool = False) -> CRet.Py_PVoid: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *args, restype: None = None, argtypes: tuple[type, ...], is_super: bool = False) -> None: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: CRet.Boolean, is_super: bool = False) -> CRet.Py_Boolean: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: CRet.Char, is_super: bool = False) -> CRet.Py_Char: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: CRet.Str, is_super: bool = False) -> CRet.Py_Str: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: CRet.Integral, is_super: bool = False) -> CRet.Py_Integral: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: CRet.CharSeq, is_super: bool = False) -> CRet.Py_CharSeq: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: CRet.StrSeq, is_super: bool = False) -> CRet.Py_StrSeq: ...
    @overload
    def send_message(self, obj: c_void_p, sel_name: bytes, *, restype: CRet.PVoid, is_super: bool = False) -> CRet.Py_PVoid: ...
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
        if not obj.value:
            raise RuntimeError(f'Failed to alloc object of class {cls.value}')
        obj = c_void_p(self.send_message(obj, init_name, restype=c_void_p, *args, argtypes=argtypes))
        if not obj.value:
            self.send_message(obj, b'release')
            raise RuntimeError(f'Failed to {init_name.decode()} object of class {cls.value}')
        return NotNull_VoidP(obj.value)

    def release_on_exit(self, obj: c_void_p):
        self._stack.callback(lambda: self.send_message(obj, b'release'))

    def safe_objc_getClass(self, name: bytes) -> NotNull_VoidP:
        Cls = c_void_p(self.objc_getClass(name))
        if not Cls.value:
            raise RuntimeError(f'Failed to get class {name.decode()}')
        return NotNull_VoidP(Cls.value)

    def make_block(self, cb: Callable, restype: Optional[type], *argtypes: type, signature: Optional[bytes] = None) -> 'ObjCBlock':
        return ObjCBlock(self, cb, restype, *argtypes, signature=signature)

    def instanceof(self, obj: c_void_p, cls: c_void_p) -> bool:
        return bool(self.send_message(
            obj, b'isKindOfClass:',
            cls, restype=c_byte, argtypes=(c_void_p, )))


class ObjCBlockDescBase(Structure):
    _fields_ = (
        ('reserved', c_ulong),
        ('size', c_ulong),
    )


class ObjCBlockDescWithSignature(ObjCBlockDescBase):
    _fields_ = (('signature', c_char_p), )


class ObjCBlock(Structure):
    _fields_ = (
        ('isa', c_void_p),
        ('flags', c_int),
        ('reserved', c_int),
        ('invoke', c_void_p),  # FnPtr
        ('desc', POINTER(ObjCBlockDescBase)),
    )
    BLOCK_ST = struct.Struct(b'@PiiPP')
    BLOCKDESC_SIGNATURE_ST = struct.Struct(b'@LLP')
    BLOCKDESC_ST = struct.Struct(b'@LL')
    BLOCK_TYPE = b'@?'

    def __init__(self, pyneapple: PyNeApple, cb: Callable, restype: Optional[type], *argtypes: type, signature: Optional[bytes] = None):
        f = 0
        if signature:  # Empty signatures are not acceptable, they should at least be v@?
            f |= 1 << 30
            self._desc = ObjCBlockDescWithSignature(reserved=0, size=sizeof(ObjCBlock), signature=signature)
        else:
            self._desc = ObjCBlockDescBase(reserved=0, size=sizeof(ObjCBlock))
        super().__init__(
            isa=pyneapple.p_NSConcreteMallocBlock,
            flags=f,
            reserved=0,
            invoke=as_fnptr(cb, restype, *argtypes),
            desc=cast(pointer(self._desc), POINTER(ObjCBlockDescBase)),
        )

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


VOIDP_ARGTYPE = Optional[int]
T = TypeVar('T')


@overload
def str_from_nsstring(pa: PyNeApple, nsstr: NotNull_VoidP) -> str: ...
@overload
def str_from_nsstring(pa: PyNeApple, nsstr: c_void_p, *, default: T = None) -> Union[str, T]: ...


def str_from_nsstring(pa: PyNeApple, nsstr: Union[c_void_p, NotNull_VoidP], *, default: T = None) -> Union[str, T]:
    return py_typecast(bytes, pa.send_message(
        nsstr, b'UTF8String', restype=c_char_p)).decode() if nsstr.value else default


navidg_cbdct: 'PFC_NaviDelegate.CBDICT_TYPE' = {}
class PFC_NaviDelegate:
    CBDICT_TYPE = dict[int, Callable[[], None]]
    SIGNATURE_WEBVIEW_DIDFINISHNAVIGATION = b'v@:@@'

    @staticmethod
    def webView0_didFinishNavigation1(this: VOIDP_ARGTYPE, sel: VOIDP_ARGTYPE, rp_webview: VOIDP_ARGTYPE, rp_navi: VOIDP_ARGTYPE) -> None:
        if cb := navidg_cbdct.get(rp_navi or 0):
            cb()

PyNeApple().load_framework_from_path('Foundation')
cf = PyNeApple().load_framework_from_path('CoreFoundation')
PyNeApple().load_framework_from_path('WebKit')
NSDictionary = PyNeApple().safe_objc_getClass(b'NSDictionary')
NSString = PyNeApple().safe_objc_getClass(b'NSString')
NSNumber = PyNeApple().safe_objc_getClass(b'NSNumber')
NSObject = PyNeApple().safe_objc_getClass(b'NSObject')
NSURL = PyNeApple().safe_objc_getClass(b'NSURL')
WKContentWorld = PyNeApple().safe_objc_getClass(b'WKContentWorld')
WKWebView = PyNeApple().safe_objc_getClass(b'WKWebView')
WKWebViewConfiguration = c_void_p(PyNeApple().objc_getClass(b'WKWebViewConfiguration'))

lstop = cfn_at(cf(b'CFRunLoopStop').value, None, c_void_p)
lrun = cfn_at(cf(b'CFRunLoopRun').value, None)
getmain = cfn_at(cf(b'CFRunLoopGetMain').value, c_void_p)
mainloop = getmain()
kcf_true = c_void_p.from_address(cf(b'kCFBooleanTrue').value)

Py_NaviDg = PyNeApple().objc_allocateClassPair(NSObject, b'PyForeignClass_NavigationDelegate', 0)
if not Py_NaviDg:
    raise RuntimeError('Failed to allocate class PyForeignClass_NavigationDelegate, did you register twice?')
PyNeApple().class_addMethod(
    Py_NaviDg, PyNeApple().sel_registerName(b'webView:didFinishNavigation:'),
    as_fnptr(PFC_NaviDelegate.webView0_didFinishNavigation1, None, c_void_p, c_void_p, c_void_p, c_void_p),
    PFC_NaviDelegate.SIGNATURE_WEBVIEW_DIDFINISHNAVIGATION)
PyNeApple().class_addProtocol(Py_NaviDg, PyNeApple().objc_getProtocol(b'WKNavigationDelegate'))
PyNeApple().objc_registerClassPair(Py_NaviDg)

with ExitStack() as exsk:
    p_cfg = PyNeApple().safe_new_object(WKWebViewConfiguration)
    exsk.callback(PyNeApple().send_message, p_cfg, b'release')

    rp_pref = c_void_p(PyNeApple().send_message(p_cfg, b'preferences', restype=c_void_p))
    if not rp_pref.value:
        raise RuntimeError('Failed to get preferences from WKWebViewConfiguration')
    PyNeApple().send_message(
        rp_pref, b'setJavaScriptCanOpenWindowsAutomatically:',
        c_byte(1), argtypes=(c_byte,))
    p_setkey0 = PyNeApple().safe_new_object(
        NSString, b'initWithUTF8String:', b'allowFileAccessFromFileURLs',
        argtypes=(c_char_p, ))
    exsk.callback(PyNeApple().send_message, p_setkey0, b'release')
    PyNeApple().send_message(
        rp_pref, b'setValue:forKey:',
        kcf_true, p_setkey0,
        argtypes=(c_void_p, c_void_p))
    rp_pref = None

    p_setkey1 = PyNeApple().safe_new_object(
        NSString, b'initWithUTF8String:', b'allowUniversalAccessFromFileURLs',
        argtypes=(c_char_p, ))
    exsk.callback(PyNeApple().send_message, p_setkey1, b'release')
    PyNeApple().send_message(
        p_cfg, b'setValue:forKey:',
        kcf_true, p_setkey1,
        argtypes=(c_void_p, c_void_p))

    p_webview = PyNeApple().safe_new_object(
        WKWebView, b'initWithFrame:configuration:',
        CGRect(), p_cfg,
        argtypes=(CGRect, c_void_p))
    PyNeApple().release_on_exit(p_webview)

p_navidg = PyNeApple().safe_new_object(Py_NaviDg)
PyNeApple().release_on_exit(p_navidg)
PyNeApple().send_message(
    p_webview, b'setNavigationDelegate:',
    p_navidg, argtypes=(c_void_p, ))

with ExitStack() as exsk:
    ps_html = PyNeApple().safe_new_object(
        NSString, b'initWithUTF8String:', rb'''<!DOCTYPE html><html lang="en"><head><title></title></head><body></body></html>''',
        argtypes=(c_char_p, ))
    exsk.callback(PyNeApple().send_message, ps_html, b'release')
    ps_base_url = PyNeApple().safe_new_object(
        NSString, b'initWithUTF8String:', rb'''https://www.youtube.com/robots.txt''',
        argtypes=(c_char_p, ))
    exsk.callback(PyNeApple().send_message, ps_base_url, b'release')
    purl_base = PyNeApple().safe_new_object(
        NSURL, b'initWithString:', ps_base_url,
        argtypes=(c_void_p, ))
    exsk.callback(PyNeApple().send_message, purl_base, b'release')

    rp_navi = NotNull_VoidP(PyNeApple().send_message(
        p_webview, b'loadHTMLString:baseURL:', ps_html, purl_base,
        restype=c_void_p, argtypes=(c_void_p, c_void_p)) or 0)

    def cb_navi_done():
        lstop(mainloop)

    navidg_cbdct[rp_navi.value] = cb_navi_done

    lrun()

jsresult_id = c_void_p()
jsresult_err = c_void_p()
with ExitStack() as exsk:
    ps_script = PyNeApple().safe_new_object(
        NSString, b'initWithUTF8String:', rb'''
return await (async ()=>{  // IIAFE
try {
// pot for browser, navigate to https://www.youtube.com/robots.txt first
const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36(KHTML, like Gecko)';
const GOOG_API_KEY = 'AIzaSyDyT5W0Jh49F30Pqqtyfdf7pDLFKLJoAnw';
const REQUEST_KEY = 'O43z0dpjhgX20SCx4KAo'
const YT_BASE_URL = 'https://www.youtube.com';
const GOOG_BASE_URL = 'https://jnn-pa.googleapis.com';

function buildURL(endpointName, useYouTubeAPI) {
return `${useYouTubeAPI ? YT_BASE_URL : GOOG_BASE_URL}/${useYouTubeAPI ? 'api/jnn/v1' : '$rpc/google.internal.waa.v1.Waa'}/${endpointName}`;
}

function u8ToBase64(u8, base64url = false) {
const result = btoa(String.fromCharCode(...u8));

if (base64url) {
return result
.replace(/\+/g, '-')
.replace(/\//g, '_');
}

return result;
}

const base64urlToBase64Map = {
'-': '+',
_: '/',
'.': '='
};

const base64urlCharRegex = /[-_.]/g;

function base64ToU8(base64) {
let base64Mod;

if (base64urlCharRegex.test(base64)) {
base64Mod = base64.replace(base64urlCharRegex, function (match) {
return base64urlToBase64Map[match];
});
} else {
base64Mod = base64;
}

base64Mod = atob(base64Mod);

return new Uint8Array(
[...base64Mod].map(
(char) => char.charCodeAt(0)
)
);
}

function descramble(scrambledChallenge) {
const buffer = base64ToU8(scrambledChallenge);
if (buffer.length)
return new TextDecoder().decode(buffer.map((b) => b + 97));
}

function parseChallengeData(rawData) {
let challengeData = [];
if (rawData.length > 1 && typeof rawData[1] === 'string') {
const descrambled = descramble(rawData[1]);
challengeData = JSON.parse(descrambled || '[]');
} else if (rawData.length && typeof rawData[0] === 'object') {
challengeData = rawData[0];
}

const [messageId, wrappedScript, wrappedUrl, interpreterHash, program, globalName, , clientExperimentsStateBlob] = challengeData;
const privateDoNotAccessOrElseSafeScriptWrappedValue = Array.isArray(wrappedScript) ? wrappedScript.find((value) => value && typeof value === 'string') : null;
const privateDoNotAccessOrElseTrustedResourceUrlWrappedValue = Array.isArray(wrappedUrl) ? wrappedUrl.find((value) => value && typeof value === 'string') : null;

return {
messageId,
interpreterJavascript: {
privateDoNotAccessOrElseSafeScriptWrappedValue,
privateDoNotAccessOrElseTrustedResourceUrlWrappedValue
},
interpreterHash,
program,
globalName,
clientExperimentsStateBlob
};
}

function isBrowser() {
const isBrowser = typeof window !== 'undefined'
&& typeof window.document !== 'undefined'
&& typeof window.document.createElement !== 'undefined'
&& typeof window.HTMLElement !== 'undefined'
&& typeof window.navigator !== 'undefined'
&& typeof window.getComputedStyle === 'function'
&& typeof window.requestAnimationFrame === 'function'
&& typeof window.matchMedia === 'function';

const hasValidWindow = Object.getOwnPropertyDescriptor(globalThis, 'window')?.get?.toString().includes('[native code]') ?? false;

return isBrowser && hasValidWindow;
}

let headers = {
'content-type': 'application/json+protobuf',
'x-goog-api-key': GOOG_API_KEY,
'x-user-agent': 'grpc-web-javascript/0.1'
};
if (!isBrowser())
headers['user-agent'] = USER_AGENT;

// fetch challenge
const payload = [REQUEST_KEY];
const resp = await fetch(buildURL('Create', false), {
method: 'POST',
headers: headers,
body: JSON.stringify(payload)
})

if (!resp.ok)
throw new Error('Failed to fetch challenge');

const rawDataJson = await resp.json();
const bgChallenge = parseChallengeData(rawDataJson);
if (!bgChallenge)
throw new Error('Could not get challenge');


const interpreterJavascript = bgChallenge.interpreterJavascript.privateDoNotAccessOrElseSafeScriptWrappedValue;

if (interpreterJavascript) {
new Function(interpreterJavascript)();
} else
throw new Error('Could not load VM');

const bg = ((vm, program, userInteractionElement) => {
if (!vm)
throw new Error('VM not found');
if (!vm.a)
throw new Error('VM init function not found');
let vmFns;
const vmFunctionsCallback = (asyncSnapshotFunction, shutdownFunction, passEventFunction, checkCameraFunction) => {
vmFns = { asyncSnapshotFunction, shutdownFunction, passEventFunction, checkCameraFunction };
};
const syncSnapshotFunction = vm.a(program, vmFunctionsCallback, true, userInteractionElement, () => {/** no-op */ }, [[], []])[0]
return { syncSnapshotFunction, vmFns };
})(globalThis[bgChallenge.globalName], bgChallenge.program, bgChallenge.userInteractionElement);

async function snapshot(vmFns, args, timeout = 3000) {
return await Promise.race([
new Promise((resolve, reject) => {
if (!vmFns.asyncSnapshotFunction)
    return reject(new Error('Asynchronous snapshot function not found'));
vmFns.asyncSnapshotFunction((response) => resolve(response), [
    args.contentBinding,
    args.signedTimestamp,
    args.webPoSignalOutput,
    args.skipPrivacyBuffer
]);
}),
new Promise((_, reject) =>
setTimeout(() => reject(new Error('VM operation timed out')), timeout)
)
]);
}


const webPoSignalOutput = [];
const botguardResponse = await snapshot(bg.vmFns, { webPoSignalOutput });
const generatePayload = [REQUEST_KEY, botguardResponse];

const integrityTokenResponse = await fetch(buildURL('GenerateIT', false), {
method: 'POST',
headers: headers,
body: JSON.stringify(generatePayload)
});
const integrityTokenJson = await integrityTokenResponse.json();
const [integrityToken, estimatedTtlSecs, mintRefreshThreshold, websafeFallbackToken] = integrityTokenJson;

const integrityTokenData = {
integrityToken,
estimatedTtlSecs,
mintRefreshThreshold,
websafeFallbackToken
};

const minter = await (async (integrityTokenResponse, webPoSignalOutput_) => {
const getMinter = webPoSignalOutput_[0];

if (!getMinter)
throw new Error('PMD:Undefined');

if (!integrityTokenResponse.integrityToken)
throw new Error('No integrity token provided');
const mintCallback = await getMinter(base64ToU8(integrityTokenResponse.integrityToken));

if (!(mintCallback instanceof Function))
throw new Error('APF:Failed');
return async (identifier) => {
const res = await ((async (identifier) => {
const result = await mintCallback(new TextEncoder().encode(identifier));
if (!result)
    throw new Error('YNJ:Undefined');
if (!(result instanceof Uint8Array))
    throw new Error('ODM:Invalid');
return result;
})(identifier));
return u8ToBase64(res, true);
};
})(integrityTokenData, webPoSignalOutput);


// // innertube is just for visitor data generation
// import { Innertube } from 'youtubei.js';

// const innertube = await Innertube.create({ user_agent: USER_AGENT, enable_session_cache: false });
// const visitorData = innertube.session.context.client.visitorData || '';

// if (!visitorData)
//     throw new Error('Could not get visitor data');


// console.log(`visitorData(generated with Innertube): ${visitorData}`);
// console.log(`GVS: ${await minter(visitorData)}`);
const pot = await minter(globalThis?.process?.argv[2] || 'dQw4w9WgXcQ');
return `:.:${document.URL}: ${pot}`;
} catch(e) {return `:E:${document.URL}: ${e}`;}
})();
''',
        argtypes=(c_char_p, ))
    exsk.callback(PyNeApple().send_message, ps_script, b'release')

    pd_jsargs = PyNeApple().safe_new_object(NSDictionary)
    exsk.callback(PyNeApple().send_message, pd_jsargs, b'release')

    rp_pageworld = c_void_p(PyNeApple().send_message(
        WKContentWorld, b'pageWorld',
        restype=c_void_p))

    def completion_handler(self: VOIDP_ARGTYPE, id_result: VOIDP_ARGTYPE, err: VOIDP_ARGTYPE):
        jsresult_id, jsresult_err
        jsresult_id = c_void_p(PyNeApple().send_message(c_void_p(id_result or 0), b'copy', restype=c_void_p))
        PyNeApple().release_on_exit(jsresult_id)
        jsresult_err = c_void_p(PyNeApple().send_message(c_void_p(err or 0), b'copy', restype=c_void_p))
        PyNeApple().release_on_exit(jsresult_err)
        lstop(mainloop)

    chblock = PyNeApple().make_block(completion_handler, None, POINTER(ObjCBlock), c_void_p, c_void_p)

    PyNeApple().send_message(
        # Requires iOS 15.0+, maybe test its availability first?
        p_webview, b'callAsyncJavaScript:arguments:inFrame:inContentWorld:completionHandler:',
        ps_script, pd_jsargs, c_void_p(None), rp_pageworld, byref(chblock),
        argtypes=(c_void_p, c_void_p, c_void_p, c_void_p, POINTER(ObjCBlock)))

    lrun()

if jsresult_err:
    code = PyNeApple().send_message(jsresult_err, b'code', restype=c_long)
    s_domain = str_from_nsstring(pa, c_void_p(PyNeApple().send_message(
        jsresult_err, b'domain', restype=c_void_p)), default='<unknown>')
    s_uinfo = str_from_nsstring(pa, c_void_p(PyNeApple().send_message(
        c_void_p(PyNeApple().send_message(jsresult_err, b'userInfo', restype=c_void_p)),
        b'description', restype=c_void_p)), default='<no description provided>')
    raise RuntimeError(f'JS failed: NSError@{jsresult_err.value}, {code=}, domain={s_domain}, user info={s_uinfo}')

if not jsresult_id:
    s_rtype = 'nothing'
    s_result = 'nil'
elif PyNeApple().instanceof(jsresult_id, NSString):
    s_rtype = 'string'
    s_result = str_from_nsstring(pa, py_typecast(NotNull_VoidP, jsresult_id))
elif PyNeApple().instanceof(jsresult_id, NSNumber):
    s_rtype = 'number'
    s_result = str_from_nsstring(pa, NotNull_VoidP(py_typecast(
        int, PyNeApple().send_message(jsresult_id, b'stringValue', restype=c_void_p))))
else:
    s_rtype = '<unknown type>'
    s_result = '<unknown>'