#define CROW_MAIN
#define ASIO_STANDALONE
#include "crow.h"
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <filesystem>

using json = nlohmann::json;
namespace fs = std::filesystem;

// ======== CORS Middleware ========
struct CORS {
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context&) {
        res.add_header("Access-Control-Allow-Origin", "https://console.arcstrum.com");
        res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.add_header("Access-Control-Allow-Credentials", "true");

        if (req.method == "OPTIONS"_method) {
            res.code = 204;
            res.end();
        }
    }

    void after_handle(crow::request&, crow::response& res, context&) {
        res.add_header("Access-Control-Allow-Origin", "https://console.arcstrum.com");
        res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.add_header("Access-Control-Allow-Credentials", "true");
    }
};

// ======== Helpers ========
std::string get_db_path(const std::string& user_id, const std::string& db_file) {
    std::string dir = "db_root/" + user_id;
    fs::create_directories(dir);
    return dir + "/" + db_file;
}

sqlite3* open_db(const std::string& path, json& error_out) {
    sqlite3* db = nullptr;
    int rc = sqlite3_open(path.c_str(), &db);
    if (rc) {
        error_out["error"] = std::string("Can't open DB: ") + sqlite3_errmsg(db);
        sqlite3_close(db);
        return nullptr;
    }
    return db;
}

crow::response error_resp(const std::string& msg, int code = 400) {
    json err;
    err["error"] = msg;
    return crow::response(code, err.dump());
}

static int select_callback(void* data, int argc, char** argv, char** colNames) {
    auto* rows = static_cast<std::vector<json>*>(data);
    json row;
    for (int i = 0; i < argc; i++) {
        row[colNames[i]] = argv[i] ? argv[i] : nullptr;
    }
    rows->push_back(row);
    return 0;
}

// ======== Main ========
int main() {
    crow::App<CORS> app;

    // Health check
    CROW_ROUTE(app, "/")([] {
        return R"({"status":"db-api online"})";
    });

    // POST /servers → open/init DB
    CROW_ROUTE(app, "/servers").methods("POST"_method)(
        [](const crow::request& req) {
            try {
                auto body = json::parse(req.body);
                std::string user_id = body.value("user_id", "");
                std::string db_file = body.value("db_file", "");
                if (user_id.empty() || db_file.empty()) return error_resp("Missing user_id or db_file");

                std::string path = get_db_path(user_id, db_file);
                json res;
                res["ok"] = true;
                res["path"] = path;
                return crow::response(res.dump());
            } catch (const std::exception& e) {
                return error_resp(e.what(), 500);
            }
        });

    CROW_ROUTE(app, "/list").methods("POST"_method)(
        [](const crow::request& req) {
            try {
                auto body = json::parse(req.body);
                std::string user_id = body.value("user_id", "");
                if (user_id.empty()) return error_resp("Missing user_id");

                std::string dir = "db_root/" + user_id;
                json res;
                std::vector<std::string> files;

                if (fs::exists(dir)) {
                    for (const auto& entry : fs::directory_iterator(dir)) {
                        if (entry.is_regular_file()) {
                            files.push_back(entry.path().filename().string());
                        }
                    }
                }

                res["files"] = files;
                return crow::response(res.dump());
            } catch (const std::exception& e) {
                return error_resp(std::string("Exception: ") + e.what(), 500);
            }
        }
    );

    // POST /query → SELECT only
    CROW_ROUTE(app, "/query").methods("POST"_method)(
        [](const crow::request& req) {
            try {
                auto body = json::parse(req.body);
                std::string user_id = body.value("user_id", "");
                std::string db_file = body.value("db_file", "");
                std::string sql = body.value("sql", "");
                if (user_id.empty() || db_file.empty() || sql.empty()) return error_resp("Missing parameters");

                if (sql.substr(0, 6) != "SELECT" && sql.substr(0, 6) != "select")
                    return error_resp("Only SELECT queries allowed");

                std::string path = get_db_path(user_id, db_file);
                json err;
                sqlite3* db = open_db(path, err);
                if (!db) return crow::response(500, err.dump());

                std::vector<json> rows;
                char* errMsg = nullptr;
                int rc = sqlite3_exec(db, sql.c_str(), select_callback, &rows, &errMsg);
                sqlite3_close(db);
                if (rc != SQLITE_OK) {
                    std::string msg = errMsg ? errMsg : "SQL error";
                    sqlite3_free(errMsg);
                    return error_resp(msg);
                }

                json res;
                res["rows"] = rows;
                return crow::response(res.dump());
            } catch (const std::exception& e) {
                return error_resp(e.what(), 500);
            }
        });

    // POST /exec → Non-SELECT statements
    CROW_ROUTE(app, "/exec").methods("POST"_method)(
        [](const crow::request& req) {
            try {
                auto body = json::parse(req.body);
                std::string user_id = body.value("user_id", "");
                std::string db_file = body.value("db_file", "");
                std::string sql = body.value("sql", "");
                if (user_id.empty() || db_file.empty() || sql.empty()) return error_resp("Missing parameters");

                std::string path = get_db_path(user_id, db_file);
                json err;
                sqlite3* db = open_db(path, err);
                if (!db) return crow::response(500, err.dump());

                char* errMsg = nullptr;
                int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
                sqlite3_close(db);
                if (rc != SQLITE_OK) {
                    std::string msg = errMsg ? errMsg : "SQL error";
                    sqlite3_free(errMsg);
                    return error_resp(msg);
                }

                json res;
                res["success"] = true;
                return crow::response(res.dump());
            } catch (const std::exception& e) {
                return error_resp(e.what(), 500);
            }
        });

    app.port(4000).multithreaded().run();
}
