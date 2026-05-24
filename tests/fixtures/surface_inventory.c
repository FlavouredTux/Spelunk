#include <stdio.h>

__attribute__((noinline))
void scripting_surface(void) {
    puts("[FLog::MacLuaApp] ScriptContext Luau heap report lua_State ModuleScript");
}

__attribute__((noinline))
void network_surface(void) {
    puts("[DFLog::RbxTransportTls] SSL_CTX_set_min_proto_version failed for QUIC transport");
}

__attribute__((noinline))
void web_shell_surface(void) {
    puts("WKWebView httpCookieStore syncAuthCookieFromWebViewToApp securityCookie MainMenu");
}

__attribute__((noinline))
void platform_surface(void) {
    puts("Crashpad updater telemetry analytics SQLite GameController Metal shader");
}

__attribute__((noinline))
void protection_surface(void) {
    puts("VMProtectSDK integrity check mimalloc heap profiler code signature debugger");
}

__attribute__((noinline))
void media_surface(void) {
    puts("CoreAudio AudioUnit AVFoundation VideoToolbox CVPixelBuffer CoreML mlmodel");
}

__attribute__((noinline))
void commerce_surface(void) {
    puts("Marketplace purchase Robux price receipt UserNotifications Contacts localization");
}

__attribute__((noinline))
void linkage_surface(void) {
    puts("@rpath/libmimalloc.3.dylib /System/Library/Frameworks/CoreML.framework/Versions/A/CoreML");
}

int main(void) {
    scripting_surface();
    network_surface();
    web_shell_surface();
    platform_surface();
    protection_surface();
    media_surface();
    commerce_surface();
    linkage_surface();
    return 0;
}
