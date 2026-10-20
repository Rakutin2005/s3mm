#include "s3mm/common/log.hpp"

#include <fcntl.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {

void handleClient(int client) {
    char buf[8192];
    ssize_t n = recv(client, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(client); return; }
    buf[n] = '\0';
    std::string req(buf, n);

    // Parse request line
    std::string method, path;
    size_t sp1 = req.find(' ');
    if (sp1 != std::string::npos) {
        method = req.substr(0, sp1);
        size_t sp2 = req.find(' ', sp1 + 1);
        if (sp2 != std::string::npos) path = req.substr(sp1 + 1, sp2 - sp1 - 1);
    }

    bool isList = path.find("list-type=2") != std::string::npos ||
                  path.find("list-type=1") != std::string::npos;

    std::string body;
    std::string status = "200 OK";
    std::string contentType = "application/xml";

    if (method == "PUT") {
        body = "";
        contentType = "text/plain";
    } else if (method == "DELETE") {
        body = "";
        contentType = "text/plain";
    } else if (isList) {
        body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
               "  <Name>bucket</Name>\n"
               "  <Prefix></Prefix>\n"
               "  <KeyCount>0</KeyCount>\n"
               "  <MaxKeys>1000</MaxKeys>\n"
               "  <IsTruncated>false</IsTruncated>\n"
               "</ListBucketResult>\n";
    } else if (path.find("/?location") != std::string::npos) {
        body = "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>";
    } else {
        body = "";
    }

    std::string resp = "HTTP/1.1 " + status + "\r\n";
    resp += "Content-Type: " + contentType + "\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += body;
    send(client, resp.c_str(), resp.size(), 0);
    close(client);
}

} // namespace

extern "C" void fakeS3Serve(int port, std::atomic<bool>& stop) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return;
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) { close(srv); return; }
    if (listen(srv, 16) < 0) { close(srv); return; }
    fcntl(srv, F_SETFL, O_NONBLOCK);
    while (!stop.load()) {
        int c = accept(srv, nullptr, nullptr);
        if (c < 0) { usleep(50000); continue; }
        std::thread(handleClient, c).detach();
    }
    close(srv);
}
