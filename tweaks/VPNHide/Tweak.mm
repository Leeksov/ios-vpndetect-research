// VPNHide — VPN-detection bypass via fishhook + MSHookFunction (jailbreak).
//   • fishhook: для main-app GOT (CF*, getifaddrs, sysctl, if_nameindex)
//   • MSHookFunction: для shared-cache функций (nw_*) которые fishhook не достанет
//     (libnetwork.dylib / libswiftNetwork.dylib живут в dyld_shared_cache).
// Substrate резолвится через dlopen — работает с libsubstrate / libellekit.

#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <CFNetwork/CFProxySupport.h>
#import <Network/Network.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <sys/sysctl.h>
#import <string.h>
#import <stdio.h>
#import <dlfcn.h>
#import "fishhook/fishhook.h"

#define VPNLog(fmt, ...) NSLog(@"[VPNHide] " fmt, ##__VA_ARGS__)

// MSHookFunction prototype (resolved at runtime — no link dependency).
typedef void (*MSHookFunction_fn)(void *symbol, void *replace, void **result);
static MSHookFunction_fn g_MSHookFunction = NULL;

// SDK already provides nw_interface_t / nw_path_t (objc-typed) and
// nw_path_enumerate_interfaces_block_t = bool(^)(nw_interface_t).
// We use them directly; only the int alias for nw_interface_type_t is local.
typedef int nw_interface_type_t_local;

typedef const char *(*nw_interface_get_name_fn)(nw_interface_t);

static const char *const kVPNNeedles[] = { "utun", "tun", "tap", "ipsec", "ppp", "wg", NULL };

static BOOL iface_name_is_vpn(const char *name) {
    if (!name) return NO;
    for (const char *const *p = kVPNNeedles; *p; p++) {
        if (strcasestr(name, *p)) return YES;
    }
    return NO;
}

static BOOL nsstring_is_vpn_iface(NSString *s) {
    if (![s isKindOfClass:[NSString class]]) return NO;
    return iface_name_is_vpn([s UTF8String]);
}

#pragma mark - CFNetworkCopySystemProxySettings

static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);

static CFDictionaryRef hook_CFNetworkCopySystemProxySettings(void) {
    CFDictionaryRef orig = orig_CFNetworkCopySystemProxySettings ?
        orig_CFNetworkCopySystemProxySettings() : NULL;
    if (!orig) return orig;

    NSDictionary *src = (__bridge NSDictionary *)orig;
    NSMutableDictionary *cleaned = [src mutableCopy];

    NSDictionary *scoped = src[@"__SCOPED__"];
    if ([scoped isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *cleanedScoped = [scoped mutableCopy];
        for (id key in scoped.allKeys) {
            if (nsstring_is_vpn_iface(key)) [cleanedScoped removeObjectForKey:key];
        }
        cleaned[@"__SCOPED__"] = cleanedScoped;
    }

    NSArray *proxyFlags = @[
        @"HTTPEnable", @"HTTPSEnable", @"FTPEnable", @"RTSPEnable",
        @"SOCKSEnable", @"ProxyAutoConfigEnable",
        @"HTTPProxy", @"HTTPSProxy", @"FTPProxy", @"RTSPProxy", @"SOCKSProxy",
        @"HTTPPort", @"HTTPSPort", @"FTPPort", @"RTSPPort", @"SOCKSPort",
        @"ProxyAutoConfigURLString"
    ];
    for (NSString *k in proxyFlags) {
        if (cleaned[k]) [cleaned removeObjectForKey:k];
    }

    CFRelease(orig);
    return (__bridge_retained CFDictionaryRef)[cleaned copy];
}

#pragma mark - CFNetworkCopyProxiesForURL

static CFArrayRef (*orig_CFNetworkCopyProxiesForURL)(CFURLRef, CFDictionaryRef);

static CFArrayRef hook_CFNetworkCopyProxiesForURL(CFURLRef url, CFDictionaryRef settings) {
    (void)url; (void)settings;
    const void *keys[]   = { (const void *)kCFProxyTypeKey };
    const void *values[] = { (const void *)kCFProxyTypeNone };
    CFDictionaryRef entry = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    const void *arr[] = { entry };
    CFArrayRef out = CFArrayCreate(kCFAllocatorDefault, arr, 1, &kCFTypeArrayCallBacks);
    CFRelease(entry);
    return out;
}

#pragma mark - nw_path_uses_interface_type

static bool (*orig_nw_path_uses_interface_type)(nw_path_t, nw_interface_type_t_local);

static bool hook_nw_path_uses_interface_type(nw_path_t path, nw_interface_type_t_local type) {
    if (type == 0) {
        VPNLog(@"nw_path_uses_interface_type(.other) → false (forced)");
        return false;
    }
    if (!orig_nw_path_uses_interface_type) return false;
    return orig_nw_path_uses_interface_type(path, type);
}

#pragma mark - nw_interface_get_type

static nw_interface_type_t_local (*orig_nw_interface_get_type)(nw_interface_t);
static nw_interface_get_name_fn   orig_nw_interface_get_name = NULL;

static nw_interface_type_t_local hook_nw_interface_get_type(nw_interface_t iface) {
    if (!orig_nw_interface_get_type) return 1;
    nw_interface_type_t_local t = orig_nw_interface_get_type(iface);
    if (t == 0 && orig_nw_interface_get_name && iface) {
        const char *name = orig_nw_interface_get_name(iface);
        if (iface_name_is_vpn(name)) {
            VPNLog(@"nw_interface_get_type(%s) was .other → forced .wifi", name ?: "?");
            return 1;
        }
    }
    return t;
}

#pragma mark - nw_interface_get_name (log + masquerade)

static const char *hook_nw_interface_get_name(nw_interface_t iface) {
    if (!orig_nw_interface_get_name) return "en0";
    const char *name = orig_nw_interface_get_name(iface);
    if (iface_name_is_vpn(name)) {
        VPNLog(@"nw_interface_get_name() = %s → masqueraded as en0", name);
        return "en0";
    }
    return name;
}

#pragma mark - nw_path_enumerate_interfaces (filter VPN)

static void (*orig_nw_path_enumerate_interfaces)(nw_path_t, nw_path_enumerate_interfaces_block_t);

static void hook_nw_path_enumerate_interfaces(nw_path_t path,
                                              nw_path_enumerate_interfaces_block_t block) {
    if (!orig_nw_path_enumerate_interfaces) return;
    if (!block) { orig_nw_path_enumerate_interfaces(path, block); return; }

    __block int total = 0, dropped = 0;
    orig_nw_path_enumerate_interfaces(path, ^bool(nw_interface_t iface) {
        total++;
        if (orig_nw_interface_get_name && iface) {
            const char *name = orig_nw_interface_get_name(iface);
            if (iface_name_is_vpn(name)) {
                dropped++;
                return true;   // continue iteration but skip user block
            }
        }
        return block(iface);
    });
    if (dropped) {
        VPNLog(@"nw_path_enumerate_interfaces: total=%d, dropped=%d VPN", total, dropped);
    }
}

#pragma mark - getifaddrs (defensive)

static int (*orig_getifaddrs)(struct ifaddrs **);
static BOOL gGetifaddrsLogged = NO;

static int hook_getifaddrs(struct ifaddrs **ifap) {
    if (!orig_getifaddrs) return -1;
    int rc = orig_getifaddrs(ifap);
    if (rc != 0 || !ifap || !*ifap) return rc;

    int dropped = 0, kept = 0;
    struct ifaddrs *head = *ifap;
    struct ifaddrs **cursor = &head;
    while (*cursor) {
        struct ifaddrs *cur = *cursor;
        if (iface_name_is_vpn(cur->ifa_name)) {
            dropped++;
            *cursor = cur->ifa_next;
        } else {
            kept++;
            cursor = &cur->ifa_next;
        }
    }
    *ifap = head;
    if (dropped && !gGetifaddrsLogged) {
        gGetifaddrsLogged = YES;
        VPNLog(@"getifaddrs: kept=%d, dropped=%d VPN ifaces (logged once)", kept, dropped);
    }
    return 0;
}

#pragma mark - sysctl / sysctlbyname (diagnostic)

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                       void *newp, size_t newlen) {
    if (name && namelen >= 2) {
        // Log MIBs of interest: CTL_NET=4 (network), CTL_KERN=1
        // For CTL_NET: name[1] = AF_ROUTE(17) → routing table; name[1]=AF_INET(2) etc.
        if (name[0] == 4 /*CTL_NET*/) {
            VPNLog(@"sysctl mib=[%d,%d,%d,%d,%d,%d] (CTL_NET, len=%u)",
                   name[0],
                   namelen > 1 ? name[1] : 0,
                   namelen > 2 ? name[2] : 0,
                   namelen > 3 ? name[3] : 0,
                   namelen > 4 ? name[4] : 0,
                   namelen > 5 ? name[5] : 0,
                   namelen);
        }
    }
    return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
}

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                             void *newp, size_t newlen) {
    if (name && (strstr(name, "net.") || strstr(name, "route") || strstr(name, "vpn") || strstr(name, "tun"))) {
        VPNLog(@"sysctlbyname(\"%s\")", name);
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
}

#pragma mark - if_nameindex (filter VPN)

static struct if_nameindex *(*orig_if_nameindex)(void);

static struct if_nameindex *hook_if_nameindex(void) {
    if (!orig_if_nameindex) return NULL;
    struct if_nameindex *list = orig_if_nameindex();
    if (!list) return NULL;
    int total = 0, dropped = 0;
    for (struct if_nameindex *p = list; p->if_index != 0 || p->if_name != NULL; p++) {
        total++;
        if (iface_name_is_vpn(p->if_name)) {
            dropped++;
            // Truncate name in-place to hide VPN identity.
            // The system owns the storage; it'll be released via if_freenameindex().
            // Replace first byte with NUL → empty name.
            if (p->if_name) ((char *)p->if_name)[0] = '\0';
        }
    }
    if (dropped) VPNLog(@"if_nameindex: total=%d, blanked %d VPN names", total, dropped);
    return list;
}

#pragma mark - Substrate resolver

static void resolve_substrate(void) {
    static const char *paths[] = {
        "/usr/lib/libsubstrate.dylib",          // classic Substrate (Cydia/Sileo)
        "/var/jb/usr/lib/libsubstrate.dylib",   // rootless jailbreaks (Dopamine etc)
        "/usr/lib/libellekit.dylib",            // ElleKit (palera1n / unc0ver newer)
        "/var/jb/usr/lib/libellekit.dylib",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        void *h = dlopen(paths[i], RTLD_LAZY | RTLD_GLOBAL);
        if (!h) continue;
        g_MSHookFunction = (MSHookFunction_fn)dlsym(h, "MSHookFunction");
        if (g_MSHookFunction) {
            VPNLog(@"resolved MSHookFunction from %s @ %p", paths[i], g_MSHookFunction);
            return;
        }
    }
    VPNLog(@"WARNING: MSHookFunction not found — nw_* hooks will be installed via fishhook only (won't catch shared-cache callers)");
}

static void install_mshook(const char *symbol, void *replace, void **orig_out) {
    void *sym = dlsym(RTLD_DEFAULT, symbol);
    if (!sym) {
        VPNLog(@"MSHook: dlsym(%s) failed", symbol);
        return;
    }
    if (!g_MSHookFunction) {
        VPNLog(@"MSHook: %s @ %p — skipped (no Substrate)", symbol, sym);
        return;
    }
    g_MSHookFunction(sym, replace, orig_out);
    VPNLog(@"MSHook: %s @ %p → hook=%p, orig=%p", symbol, sym, replace, orig_out ? *orig_out : NULL);
}

#pragma mark - Constructor

__attribute__((constructor))
static void VPNHideInit(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"<no-bundle>";
    VPNLog(@"loaded into %@", bid);

    // Resolve Substrate first.
    resolve_substrate();

    // 1) MSHookFunction for shared-cache nw_* — catches calls from libswiftNetwork etc.
    //    Resolve nw_interface_get_name eagerly so other hooks can use it.
    orig_nw_interface_get_name =
        (nw_interface_get_name_fn)dlsym(RTLD_DEFAULT, "nw_interface_get_name");
    install_mshook("nw_path_uses_interface_type",
                   (void *)hook_nw_path_uses_interface_type,
                   (void **)&orig_nw_path_uses_interface_type);
    install_mshook("nw_interface_get_type",
                   (void *)hook_nw_interface_get_type,
                   (void **)&orig_nw_interface_get_type);
    install_mshook("nw_interface_get_name",
                   (void *)hook_nw_interface_get_name,
                   (void **)&orig_nw_interface_get_name);
    install_mshook("nw_path_enumerate_interfaces",
                   (void *)hook_nw_path_enumerate_interfaces,
                   (void **)&orig_nw_path_enumerate_interfaces);

    // 2) fishhook for main-app GOT (CF*, getifaddrs, sysctl, if_nameindex).
    struct rebinding rs[] = {
        { "CFNetworkCopySystemProxySettings",
          (void *)hook_CFNetworkCopySystemProxySettings,
          (void **)&orig_CFNetworkCopySystemProxySettings },
        { "CFNetworkCopyProxiesForURL",
          (void *)hook_CFNetworkCopyProxiesForURL,
          (void **)&orig_CFNetworkCopyProxiesForURL },
        { "getifaddrs",
          (void *)hook_getifaddrs,
          (void **)&orig_getifaddrs },
        { "sysctl",
          (void *)hook_sysctl,
          (void **)&orig_sysctl },
        { "sysctlbyname",
          (void *)hook_sysctlbyname,
          (void **)&orig_sysctlbyname },
        { "if_nameindex",
          (void *)hook_if_nameindex,
          (void **)&orig_if_nameindex },
    };
    int rc = rebind_symbols(rs, sizeof(rs) / sizeof(rs[0]));
    VPNLog(@"fishhook rc=%d, captured: CFSysProxy=%p CFProxiesURL=%p getifaddrs=%p sysctl=%p sysctlbyname=%p if_nameindex=%p",
           rc,
           orig_CFNetworkCopySystemProxySettings,
           orig_CFNetworkCopyProxiesForURL,
           orig_getifaddrs,
           orig_sysctl,
           orig_sysctlbyname,
           orig_if_nameindex);
}
