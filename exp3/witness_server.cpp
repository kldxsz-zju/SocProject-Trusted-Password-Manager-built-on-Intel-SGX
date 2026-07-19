#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

static std::map<std::string, std::uint64_t> load_db(const std::string &path) {
    std::map<std::string, std::uint64_t> db;
    std::ifstream in(path);
    std::string id; std::uint64_t version;
    while (in >> id >> version) db[id] = version;
    return db;
}

static bool save_db(const std::string &path, const std::map<std::string, std::uint64_t> &db) {
    const std::string tmp = path + ".tmp";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) return false;
    for (const auto &item : db) out << item.first << ' ' << item.second << '\n';
    out.flush(); out.close();
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

static std::string handle(const std::string &line, const std::string &db_path) {
    std::istringstream in(line);
    std::string op, vault_id, extra;
    std::uint64_t version = 0;
    if (!(in >> op >> vault_id >> version) || (in >> extra) || vault_id.size() != 32)
        return "ERROR bad_request\n";
    for (char c : vault_id)
        if (!std::isxdigit(static_cast<unsigned char>(c))) return "ERROR bad_vault_id\n";

    auto db = load_db(db_path);
    const std::uint64_t trusted = db.count(vault_id) ? db[vault_id] : 0;
    if (op == "COMMIT") {
        if (version < trusted) return "ROLLBACK " + std::to_string(trusted) + "\n";
        db[vault_id] = version;
        if (!save_db(db_path, db)) return "ERROR database_write\n";
        return "OK " + std::to_string(version) + "\n";
    }
    if (op == "CHECK") {
        if (trusted == 0) return "UNREGISTERED 0\n";
        if (version < trusted) return "ROLLBACK " + std::to_string(trusted) + "\n";
        if (version > trusted) return "UNCOMMITTED " + std::to_string(trusted) + "\n";
        return "OK " + std::to_string(trusted) + "\n";
    }
    return "ERROR bad_operation\n";
}

int main(int argc, char **argv) {
    const int port = argc > 1 ? std::atoi(argv[1]) : 8765;
    const std::string db_path = argc > 2 ? argv[2] : "witness_versions.db";
    int server = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1; setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    if (server < 0 || bind(server, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0 ||
        listen(server, 16) < 0) { std::cerr << "witness_server: " << std::strerror(errno) << '\n'; return 1; }
    std::cout << "Witness listening on 0.0.0.0:" << port << ", db=" << db_path << std::endl;
    for (;;) {
        int client = accept(server, nullptr, nullptr); if (client < 0) continue;
        std::string request; char ch;
        while (request.size() < 256 && read(client, &ch, 1) == 1 && ch != '\n') request += ch;
        const std::string response = handle(request, db_path);
        (void)write(client, response.data(), response.size()); close(client);
    }
}
