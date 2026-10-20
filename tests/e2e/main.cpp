#include "s3mm/s3/http.hpp"
#include "s3mm/common/fs.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

extern "C" void fakeS3Serve(int port, std::atomic<bool>& stop);

int main() {
    std::atomic<bool> stop{false};
    const int port = 18081;
    std::thread srv(fakeS3Serve, port, std::ref(stop));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    s3mm::http::initGlobal();
    s3mm::http::Client client;
    s3mm::http::Request req;
    req.method = "GET";
    req.url = "http://127.0.0.1:" + std::to_string(port) + "/bucket?list-type=2&prefix=";
    auto resp = client.send(req);
    printf("status=%ld\n", resp.status);
    bool ok = (resp.status == 200) && (resp.body.find("ListBucketResult") != std::string::npos);

    // PUT + DELETE smoke
    s3mm::http::Request putReq;
    putReq.method = "PUT";
    putReq.url = "http://127.0.0.1:" + std::to_string(port) + "/bucket/key.txt";
    putReq.body = "hello";
    auto putResp = client.send(putReq);
    printf("put status=%ld\n", putResp.status);
    ok = ok && (putResp.status == 200);

    stop.store(true);
    srv.join();
    return ok ? 0 : 1;
}
