from std.sys import argv
from std.sys.info import CompilationTarget
from std.ffi import OwnedDLHandle, RTLD, c_int
from std.memory import Pointer
from std.time import perf_counter_ns
from std.math import log

comptime DOH = "https://1.1.1.1/dns-query"


@fieldwise_init
struct PhaseStats(Copyable, Movable):
    var steady_p50: Float64
    var p25: Float64
    var p75: Float64
    var early_p50: Float64
    var burst_ratio: Float64
    var loaded_rtt_p50: Float64
    var total_bytes: Int
    var ok_count: Int
    var host_bytes: List[Int]
    var host_ips: List[String]


def next_u64(mut state: UInt64) -> UInt64:
    state += 0x9E3779B97F4A7C15
    var z = (state ^ (state >> 30)) * 0xBF58476D1CE4E5B9
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB
    return z ^ (z >> 31)


def next_unit(mut state: UInt64) -> Float64:
    return (Float64(next_u64(state) >> 11) + 1.0) / 9007199254740992.0


def write_cb(ptr: Int, size: Int, nmemb: Int, slot: Pointer[Int, MutAnyOrigin]) -> Int:
    var n = size * nmemb
    slot[] += n
    return n


def sink_cb(ptr: Int, size: Int, nmemb: Int, ud: Int) -> Int:
    return size * nmemb


def read_cb(buf: Pointer[UInt64, MutAnyOrigin], size: Int, nmemb: Int, st: Pointer[UInt64, MutAnyOrigin]) -> Int:
    var rem = Int(st.unsafe_offset(2)[])
    if rem <= 0:
        return 0
    var cap = size * nmemb
    if cap > rem:
        cap = rem
    var s = st[]
    var words = cap >> 3
    if words == 0:
        Pointer[UInt8, MutAnyOrigin](unsafe_from_address=Int(buf))[] = UInt8(next_u64(s) & 0xFF)
        st[] = s
        st.unsafe_offset(1)[] += 1
        st.unsafe_offset(2)[] = UInt64(rem - 1)
        return 1
    for i in range(words):
        buf.unsafe_offset(i)[] = next_u64(s)
    var n = words << 3
    st[] = s
    st.unsafe_offset(1)[] += UInt64(n)
    st.unsafe_offset(2)[] = UInt64(rem - n)
    return n


def open_curl() raises -> OwnedDLHandle:
    comptime if CompilationTarget.is_macos():
        return OwnedDLHandle("/usr/lib/libcurl.4.dylib", RTLD.NOW)
    var paths: List[String] = [
        "libcurl.so.4",
        "/usr/local/lib/libcurl.so.4",
        "libcurl-gnutls.so.4",
        "libcurl.so",
        "/usr/local/lib/libcurl.so",
    ]
    for i in range(len(paths)):
        try:
            return OwnedDLHandle(paths[i], RTLD.NOW)
        except:
            pass
    return OwnedDLHandle("libcurl.so.4", RTLD.NOW)


def setopt[T: TrivialRegisterPassable](lib: OwnedDLHandle, easy: Int, opt: Int, val: T):
    comptime if CompilationTarget.is_macos() and CompilationTarget.is_apple_silicon():
        _ = lib.call["curl_easy_setopt", c_int](easy, opt, 0, 0, 0, 0, 0, 0, val)
    else:
        _ = lib.call["curl_easy_setopt", c_int](easy, opt, val)


def setopt_str(lib: OwnedDLHandle, easy: Int, opt: Int, var s: String):
    setopt(lib, easy, opt, s.as_c_string_span().ptr())
    _ = s.byte_length()


def getinfo_int(lib: OwnedDLHandle, easy: Int, info: Int) -> Int:
    var out: Int = 0
    comptime if CompilationTarget.is_macos() and CompilationTarget.is_apple_silicon():
        _ = lib.call["curl_easy_getinfo", c_int](easy, info, 0, 0, 0, 0, 0, 0, Pointer(to=out))
    else:
        _ = lib.call["curl_easy_getinfo", c_int](easy, info, Pointer(to=out))
    return out


def getinfo_str(lib: OwnedDLHandle, easy: Int, info: Int) -> String:
    var addr = getinfo_int(lib, easy, info)
    if addr == 0:
        return ""
    var p = Pointer[UInt8, ImmutAnyOrigin](unsafe_from_address=addr)
    return "" if p[] == 0 else String(unsafe_from_utf8_ptr=p)


def configure_common(lib: OwnedDLHandle, easy: Int, url: String):
    setopt_str(lib, easy, 10002, url)
    setopt_str(lib, easy, 10279, DOH)
    setopt_str(lib, easy, 10018, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15")
    setopt(lib, easy, 84, 4)
    setopt(lib, easy, 43, 1)
    setopt(lib, easy, 99, 1)
    setopt(lib, easy, 121, 1)
    setopt(lib, easy, 98, 262144)
    setopt(lib, easy, 156, 6000)


def quantile(xs: List[Float64], q: Float64) -> Float64:
    var n = len(xs)
    if n == 0:
        return 0.0
    var cp = xs.copy()
    sort(cp)
    var pos = q * Float64(n - 1)
    var lo = Int(pos)
    var hi = lo + 1 if lo + 1 < n else lo
    var frac = pos - Float64(lo)
    return cp[lo] * (1.0 - frac) + cp[hi] * frac


def fmt(x: Float64, places: Int = 2) -> String:
    var scale = 1.0
    for _ in range(places):
        scale *= 10.0
    var sign = "-" if x < 0.0 else ""
    var v = -x if x < 0.0 else x
    var rounded = Int(v * scale + 0.5)
    var iscale = Int(scale)
    var frac = String(rounded % iscale)
    while frac.byte_length() < places:
        frac = "0" + frac
    return sign + String(rounded // iscale) + "." + frac


def measure_idle_rtt(lib: OwnedDLHandle, probe_multi: Int, probe_easy: Int, mut seed: UInt64) -> Tuple[Float64, Float64, Float64, Float64, Float64]:
    var doh_ms = 0.0
    var tcp_ms = 0.0
    var tls_ms = 0.0
    var rtts = List[Float64]()
    for i in range(9):
        var b = Int(next_u64(seed) % 1000000)
        setopt_str(lib, probe_easy, 10007, String(b) + "-" + String(b))
        _ = lib.call["curl_multi_add_handle", c_int](probe_multi, probe_easy)
        var running: c_int = 1
        while running > 0:
            _ = lib.call["curl_multi_perform", c_int](probe_multi, Pointer(to=running))
            if running > 0:
                var nfds: c_int = 0
                _ = lib.call["curl_multi_poll", c_int](probe_multi, 0, 0, 20, Pointer(to=nfds))
        var msgs: c_int = 0
        _ = lib.call["curl_multi_info_read", Int](probe_multi, Pointer(to=msgs))
        _ = lib.call["curl_multi_remove_handle", c_int](probe_multi, probe_easy)
        var code = getinfo_int(lib, probe_easy, 0x200002)
        var dns_us = getinfo_int(lib, probe_easy, 6291507)
        var tcp_us = getinfo_int(lib, probe_easy, 6291508)
        var tls_us = getinfo_int(lib, probe_easy, 6291512)
        var pre_us = getinfo_int(lib, probe_easy, 6291509)
        var stt_us = getinfo_int(lib, probe_easy, 6291510)
        if i == 0:
            setopt(lib, probe_easy, 74, 0)
            doh_ms = Float64(dns_us) / 1000.0
            tcp_ms = Float64(tcp_us - dns_us) / 1000.0 if tcp_us > dns_us else 0.0
            tls_ms = Float64(tls_us - tcp_us) / 1000.0 if tls_us > tcp_us else 0.0
        elif code >= 200 and code < 300 and stt_us > pre_us:
            rtts.append(Float64(stt_us - pre_us) / 1000.0)
    var diffs = List[Float64]()
    for j in range(1, len(rtts)):
        var d = rtts[j] - rtts[j - 1]
        diffs.append(-d if d < 0.0 else d)
    return (doh_ms, tcp_ms, tls_ms, quantile(rtts, 0.50), quantile(diffs, 0.50))


def verify_upload(lib: OwnedDLHandle, url: String, mut seed: UInt64) -> Bool:
    var easy = lib.call["curl_easy_init", Int]()
    configure_common(lib, easy, url)
    var h1 = "Expect:"
    var h2 = "Content-Type: application/octet-stream"
    var hdrs = lib.call["curl_slist_append", Int](0, h1.as_c_string_span().ptr())
    hdrs = lib.call["curl_slist_append", Int](hdrs, h2.as_c_string_span().ptr())
    var st: List[UInt64] = [next_u64(seed), 0, 65536]
    setopt(lib, easy, 47, 1)
    setopt(lib, easy, 10023, hdrs)
    setopt(lib, easy, 20012, read_cb)
    setopt(lib, easy, 10009, Int(Pointer(to=st[0])))
    setopt(lib, easy, 20011, sink_cb)
    setopt(lib, easy, 30120, 65536)
    setopt(lib, easy, 155, 8000)
    var rc = lib.call["curl_easy_perform", c_int](easy)
    var code = getinfo_int(lib, easy, 0x200002)
    lib.call["curl_slist_free_all"](hdrs)
    lib.call["curl_easy_cleanup"](easy)
    return rc == 0 and code >= 200 and code < 300 and st[1] > 0


def run_phase(lib: OwnedDLHandle, urls: List[String], sizes: List[Int], probe_multi: Int, probe_easy: Int, streams: Int, duration_s: Float64, upload: Bool, mut seed: UInt64) -> PhaseStats:
    var n_hosts = len(urls)
    var bulk_multi = lib.call["curl_multi_init", Int]()
    var handles = List[Int](length=streams, fill=0)
    var active = List[Bool](length=streams, fill=False)
    var launch_ns = List[Int](length=streams, fill=0)
    var down_slots = List[Int](length=streams, fill=0)
    var up_states = List[UInt64](length=streams * 3, fill=0)
    var host_bytes = List[Int](length=n_hosts, fill=0)
    var host_ips = List[String](length=n_hosts, fill="")
    var hdrs = 0
    if upload:
        var h1 = "Expect:"
        var h2 = "Content-Type: application/octet-stream"
        hdrs = lib.call["curl_slist_append", Int](0, h1.as_c_string_span().ptr())
        hdrs = lib.call["curl_slist_append", Int](hdrs, h2.as_c_string_span().ptr())

    var init_ns = Int(perf_counter_ns())
    var cursor_ns = init_ns
    for i in range(streams):
        var h = lib.call["curl_easy_init", Int]()
        handles[i] = h
        configure_common(lib, h, urls[i % n_hosts])
        if upload:
            up_states[i * 3] = next_u64(seed)
            setopt(lib, h, 47, 1)
            setopt(lib, h, 10023, hdrs)
            setopt(lib, h, 20012, read_cb)
            setopt(lib, h, 10009, Int(Pointer(to=up_states[i * 3])))
            setopt(lib, h, 20011, sink_cb)
            setopt(lib, h, 30120, 67108864)
        else:
            setopt(lib, h, 20011, write_cb)
            setopt(lib, h, 10001, Int(Pointer(to=down_slots[i])))
        if i > 0:
            var gap = -0.07 * log(next_unit(seed))
            cursor_ns += Int((0.30 if gap > 0.30 else gap) * 1_000_000_000.0)
        launch_ns[i] = cursor_ns

    var started = False
    var stop_ns = init_ns + Int((duration_s + 8.0) * 1_000_000_000.0)
    var warmup_ns = 0
    var warmup_s = 1.5 if duration_s >= 6.0 else duration_s * 0.25
    var prev_bucket_ns = 0
    var prev_bytes = 0
    var samples = List[Float64]()
    var loaded_rtts = List[Float64]()
    var probe_busy = False
    var next_probe_ns = 0
    var ok_count = 0

    while True:
        var now = Int(perf_counter_ns())
        if now >= stop_ns:
            break
        for i in range(streams):
            if not active[i] and now >= launch_ns[i]:
                var p = i % n_hosts
                if upload:
                    up_states[i * 3 + 2] = 67108864
                elif sizes[p] > 0:
                    var max_chunk = sizes[p] // 2
                    var chunk = 16777216 + Int(next_u64(seed) % 16777216)
                    if chunk > max_chunk:
                        chunk = max_chunk
                    var off = Int(next_u64(seed) % UInt64(sizes[p] - chunk))
                    setopt_str(lib, handles[i], 10007, String(off) + "-" + String(off + chunk - 1))
                _ = lib.call["curl_multi_add_handle", c_int](bulk_multi, handles[i])
                active[i] = True

        if started and probe_easy != 0 and not probe_busy and now >= next_probe_ns:
            var b = Int(next_u64(seed) % 1000000)
            setopt_str(lib, probe_easy, 10007, String(b) + "-" + String(b))
            _ = lib.call["curl_multi_add_handle", c_int](probe_multi, probe_easy)
            probe_busy = True

        var running_bulk: c_int = 0
        _ = lib.call["curl_multi_perform", c_int](bulk_multi, Pointer(to=running_bulk))
        if probe_busy:
            var running_probe: c_int = 0
            _ = lib.call["curl_multi_perform", c_int](probe_multi, Pointer(to=running_probe))
            var pmsgs: c_int = 0
            if lib.call["curl_multi_info_read", Int](probe_multi, Pointer(to=pmsgs)) != 0:
                _ = lib.call["curl_multi_remove_handle", c_int](probe_multi, probe_easy)
                probe_busy = False
                var pcode = getinfo_int(lib, probe_easy, 0x200002)
                var pre_us = getinfo_int(lib, probe_easy, 6291509)
                var stt_us = getinfo_int(lib, probe_easy, 6291510)
                if pcode >= 200 and pcode < 300 and stt_us > pre_us:
                    loaded_rtts.append(Float64(stt_us - pre_us) / 1000.0)
                next_probe_ns = Int(perf_counter_ns()) + 400_000_000

        while True:
            var bmsgs: c_int = 0
            var msg_addr = lib.call["curl_multi_info_read", Int](bulk_multi, Pointer(to=bmsgs))
            if msg_addr == 0:
                break
            var msg = Pointer[Int, ImmutAnyOrigin](unsafe_from_address=msg_addr)
            if (msg[] & 0xFFFFFFFF) == 1:
                var eh = msg.unsafe_offset(1)[]
                var rc = msg.unsafe_offset(2)[] & 0xFFFFFFFF
                for i in range(streams):
                    if handles[i] == eh:
                        _ = lib.call["curl_multi_remove_handle", c_int](bulk_multi, eh)
                        active[i] = False
                        var code = getinfo_int(lib, eh, 0x200002)
                        var p = i % n_hosts
                        if rc == 0 and code >= 200 and code < 300:
                            ok_count += 1
                            if host_ips[p].byte_length() == 0:
                                host_ips[p] = getinfo_str(lib, eh, 1048608)
                            var j = -0.015 * log(next_unit(seed))
                            launch_ns[i] = Int(perf_counter_ns()) + Int((0.08 if j > 0.08 else j) * 1_000_000_000.0)
                        else:
                            launch_ns[i] = Int(perf_counter_ns()) + 750_000_000
                        break

        var cur_bytes = 0
        for i in range(streams):
            cur_bytes += Int(up_states[i * 3 + 1]) if upload else down_slots[i]

        now = Int(perf_counter_ns())
        if not started and cur_bytes > 0:
            started = True
            stop_ns = now + Int(duration_s * 1_000_000_000.0)
            warmup_ns = now + Int(warmup_s * 1_000_000_000.0)
            next_probe_ns = warmup_ns
            prev_bucket_ns = now
            prev_bytes = cur_bytes

        if started and now - prev_bucket_ns >= 250_000_000:
            var mbps = Float64(cur_bytes - prev_bytes) * 8000.0 / Float64(now - prev_bucket_ns)
            if now > warmup_ns:
                samples.append(mbps)
            prev_bucket_ns = now
            prev_bytes = cur_bytes

        var nfds: c_int = 0
        _ = lib.call["curl_multi_poll", c_int](bulk_multi, 0, 0, 2 if probe_busy else 15, Pointer(to=nfds))

    if probe_busy:
        _ = lib.call["curl_multi_remove_handle", c_int](probe_multi, probe_easy)

    var total_bytes = 0
    for i in range(streams):
        if active[i]:
            var p = i % n_hosts
            if host_ips[p].byte_length() == 0:
                host_ips[p] = getinfo_str(lib, handles[i], 1048608)
            _ = lib.call["curl_multi_remove_handle", c_int](bulk_multi, handles[i])
        var b = Int(up_states[i * 3 + 1]) if upload else down_slots[i]
        host_bytes[i % n_hosts] += b
        total_bytes += b
        lib.call["curl_easy_cleanup"](handles[i])

    if hdrs != 0:
        lib.call["curl_slist_free_all"](hdrs)
    _ = lib.call["curl_multi_cleanup", c_int](bulk_multi)

    var early = List[Float64]()
    var steady = List[Float64]()
    var split = len(samples) // 3
    if split < 1 and len(samples) > 1:
        split = 1
    for idx in range(len(samples)):
        if idx < split:
            early.append(samples[idx])
        else:
            steady.append(samples[idx])
    if len(steady) == 0:
        steady = samples.copy()

    var steady_p50 = quantile(steady, 0.50)
    var early_p50 = quantile(early, 0.50) if len(early) > 0 else steady_p50
    var burst = early_p50 / steady_p50 if steady_p50 > 0.0 else 0.0
    return PhaseStats(steady_p50, quantile(steady, 0.25), quantile(steady, 0.75), early_p50, burst, quantile(loaded_rtts, 0.50), total_bytes, ok_count, host_bytes^, host_ips^)


def main() raises:
    var duration_s = 10.0
    var streams = 10
    var down_url = ""
    var up_url = ""
    var compare = False

    var args = argv()
    var i = 1
    while i < len(args):
        var a = String(args[i])
        if a == "--seconds" and i + 1 < len(args):
            duration_s = atof(String(args[i + 1]))
            i += 2
        elif a == "--streams" and i + 1 < len(args):
            streams = atol(String(args[i + 1]))
            i += 2
        elif a == "--down" and i + 1 < len(args):
            down_url = String(args[i + 1])
            i += 2
        elif a == "--up" and i + 1 < len(args):
            up_url = String(args[i + 1])
            i += 2
        elif a == "--compare":
            compare = True
            i += 1
        else:
            i += 1

    var lib = open_curl()
    _ = lib.call["curl_global_init", c_int](3)

    var labels: List[String] = ["fastly     ", "cloudflare ", "google     ", "cloudfront ", "akamai     "]
    var urls: List[String] = [
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.1.tar.xz",
        "https://nodejs.org/dist/v22.11.0/node-v22.11.0-darwin-arm64.tar.gz",
        "https://dl.google.com/go/go1.23.3.darwin-arm64.tar.gz",
        "https://corretto.aws/downloads/resources/21.0.13.1.2/amazon-corretto-21.0.13.1.2-macosx-aarch64.pkg",
        "https://builds.dotnet.microsoft.com/dotnet/Sdk/8.0.404/dotnet-sdk-8.0.404-osx-arm64.tar.gz",
    ]
    var sizes: List[Int] = [140010660, 47807451, 71639942, 200417349, 206304527]
    if down_url.byte_length() > 0:
        labels = ["custom     "]
        urls = [down_url]
        sizes = [134217728]

    var seed = UInt64(perf_counter_ns()) ^ 0xA5A5F0F012345678
    var probe_multi = lib.call["curl_multi_init", Int]()
    var probe_easy = lib.call["curl_easy_init", Int]()
    configure_common(lib, probe_easy, urls[0])
    setopt(lib, probe_easy, 74, 1)
    setopt(lib, probe_easy, 20011, sink_cb)

    print("resolver   doh", DOH, "| transport tls+h2 port 443")
    var idle = measure_idle_rtt(lib, probe_multi, probe_easy, seed)
    print("handshake  doh", fmt(idle[0], 1) + " ms | tcp", fmt(idle[1], 1) + " ms | tls", fmt(idle[2], 1) + " ms")
    print("idle rtt   p50", fmt(idle[3], 2) + " ms | jitter", fmt(idle[4], 2) + " ms")

    var down = run_phase(lib, urls, sizes, probe_multi, probe_easy, streams, duration_s, False, seed)
    var bloat = down.loaded_rtt_p50 - idle[3] if down.loaded_rtt_p50 > idle[3] else 0.0
    print("download   steady p50", fmt(down.steady_p50, 2) + " Mbps | iqr", fmt(down.p25, 2) + ".." + fmt(down.p75, 2) + " Mbps | early", fmt(down.early_p50, 2) + " Mbps | burst ratio", fmt(down.burst_ratio, 2) + "x")
    print("loaded rtt p50", fmt(down.loaded_rtt_p50, 2) + " ms | queue inflation +" + fmt(bloat, 2) + " ms")
    for p in range(len(urls)):
        var mb = Float64(down.host_bytes[p]) / 1000000.0
        var share = Float64(down.host_bytes[p]) * 100.0 / Float64(down.total_bytes) if down.total_bytes > 0 else 0.0
        var ip = down.host_ips[p] if down.host_ips[p].byte_length() > 0 else "pending"
        print("  backbone", labels[p], fmt(mb, 1) + " MB (" + fmt(share, 1) + "%) via", ip)

    if up_url.byte_length() > 0:
        if not verify_upload(lib, up_url, seed):
            print("upload     endpoint did not return 2xx for POST body")
        else:
            var up_streams = 4 if streams > 4 else streams
            var u_urls: List[String] = [up_url]
            var u_sizes: List[Int] = [0]
            var up = run_phase(lib, u_urls, u_sizes, probe_multi, probe_easy, up_streams, duration_s, True, seed)
            print("upload     steady p50", fmt(up.steady_p50, 2) + " Mbps | iqr", fmt(up.p25, 2) + ".." + fmt(up.p75, 2) + " Mbps | burst ratio", fmt(up.burst_ratio, 2) + "x")

    if compare:
        var cd_urls: List[String] = ["https://speed.cloudflare.com/__down?bytes=33554432"]
        var cu_urls: List[String] = ["https://speed.cloudflare.com/__up"]
        var c_sizes: List[Int] = [0]
        var c_down = run_phase(lib, cd_urls, c_sizes, 0, 0, streams, duration_s, False, seed)
        var c_up = run_phase(lib, cu_urls, c_sizes, 0, 0, 4, duration_s, True, seed)
        var ratio = c_down.steady_p50 / down.steady_p50 if down.steady_p50 > 0.0 else 0.0
        print("compare    known speedtest down p50", fmt(c_down.steady_p50, 2) + " Mbps | up p50", fmt(c_up.steady_p50, 2) + " Mbps | known/stealth ratio", fmt(ratio, 2) + "x")

    lib.call["curl_easy_cleanup"](probe_easy)
    _ = lib.call["curl_multi_cleanup", c_int](probe_multi)
    lib.call["curl_global_cleanup"]()
