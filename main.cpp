#define CROW_MAIN
#define ASIO_STANDALONE
#include "crow.h"
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

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

    CROW_ROUTE(app, "/")([] {
        return R"({"status":"db-api online"})";
    });

    // === All endpoints inlined below ===

    // --- CREATE DB ---
    CROW_ROUTE(app, "/servers").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string db_file = body.value("db_file", "");

            if (user_id.empty() || db_file.empty())
                return error_resp("Missing user_id or db_file");

            std::string path = get_db_path(user_id, db_file);
            fs::create_directories("db_root/" + user_id);

            json dummy_response;
            sqlite3* db = open_db(path, dummy_response);
            if (!db) return crow::response(500, dummy_response.dump());

            const char* sql = R"(
                CREATE TABLE IF NOT EXISTS __init__ (id INTEGER);
                INSERT INTO __init__ (id) VALUES (1);
                DELETE FROM __init__ WHERE id = 1;
            )";

            char* errMsg = nullptr;
            int rc = sqlite3_exec(db, sql, nullptr, nullptr, &errMsg);
            if (rc != SQLITE_OK) {
                std::string msg = errMsg ? errMsg : "SQL error";
                sqlite3_free(errMsg);
                sqlite3_close(db);
                return error_resp(msg);
            }

            sqlite3_close(db);
            json res;
            res["success"] = true;
            res["path"] = path;
            return crow::response(res.dump());

        } catch (const std::exception& e) {
            return error_resp(std::string("Exception: ") + e.what(), 500);
        }
    });

    // --- LIST DB FILES ---
    CROW_ROUTE(app, "/list").methods("POST"_method)([](const crow::request& req) {
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
    });

    // --- QUERY (SELECT ONLY) ---
    CROW_ROUTE(app, "/query").methods("POST"_method)([](const crow::request& req) {
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

    // --- EXEC (NON-SELECT) ---
    CROW_ROUTE(app, "/exec").methods("POST"_method)([](const crow::request& req) {
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

    // --- TABLES ---
    CROW_ROUTE(app, "/tables").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        if (!user_id || !db_file)
            return error_resp("Missing user_id or db_file");

        std::string path = get_db_path(user_id, db_file);
        json err;
        sqlite3* db = open_db(path, err);
        if (!db) return crow::response(500, err.dump());

        std::vector<json> tables;
        const char* sql = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';";
        char* errMsg = nullptr;

        auto cb = [](void* data, int argc, char** argv, char**) {
            auto* list = static_cast<std::vector<json>*>(data);
            if (argc > 0 && argv[0]) list->push_back(argv[0]);
            return 0;
        };

        int rc = sqlite3_exec(db, sql, cb, &tables, &errMsg);
        sqlite3_close(db);
        if (rc != SQLITE_OK) {
            std::string msg = errMsg ? errMsg : "SQL error";
            sqlite3_free(errMsg);
            return error_resp(msg);
        }

        json res;
        res["tables"] = tables;
        return crow::response(res.dump());
    });

    // --- TABLE SCHEMA ---
// --- TABLE SCHEMA ---
CROW_ROUTE(app, "/table_schema").methods("GET"_method)([](const crow::request& req) {
    const char* user_id_c = req.url_params.get("user_id");
    const char* db_file_c = req.url_params.get("db_file");
    const char* table_c   = req.url_params.get("table");

    if (!user_id_c || !db_file_c || !table_c)
        return error_resp("Missing required parameters");

    std::string user_id(user_id_c);
    std::string db_file(db_file_c);
    std::string table(table_c);

    if (table.empty())
        return error_resp("Table name is empty");

    std::string path = get_db_path(user_id, db_file);
    json err;
    sqlite3* db = open_db(path, err);
    if (!db) return crow::response(500, err.dump());

    std::vector<json> cols;
    std::string sql = "PRAGMA table_info('" + table + "');";
    char* errMsg = nullptr;

    auto cb = [](void* data, int argc, char** argv, char** colNames) {
        auto* list = static_cast<std::vector<json>*>(data);
        json col;
        for (int i = 0; i < argc; ++i)
            col[colNames[i]] = argv[i] ? argv[i] : nullptr;
        list->push_back(col);
        return 0;
    };

    int rc = sqlite3_exec(db, sql.c_str(), cb, &cols, &errMsg);
    sqlite3_close(db);

    if (rc != SQLITE_OK) {
        std::string msg = errMsg ? errMsg : "SQL error";
        sqlite3_free(errMsg);
        return error_resp(msg);
    }

    json res;
    res["columns"] = cols;
    return crow::response(res.dump());
});

    // --- INSERT ROW ---
    CROW_ROUTE(app, "/insert_row").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string db_file = body.value("db_file", "");
            std::string table = body.value("table", "");
            json row = body.value("row", json::object());
            if (user_id.empty() || db_file.empty() || table.empty() || row.empty())
                return error_resp("Missing required fields");

            std::string sql = "INSERT INTO " + table + " (";
            std::string values_clause = "VALUES (";
            bool first = true;
            for (auto it = row.begin(); it != row.end(); ++it) {
                if (!first) {
                    sql += ", ";
                    values_clause += ", ";
                }
                sql += it.key();
                values_clause += "'" + it.value().get<std::string>() + "'";
                first = false;
            }
            sql += ") " + values_clause + ")";

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

            return crow::response(R"({"success":true})");
        } catch (const std::exception& e) {
            return error_resp(e.what(), 500);
        }
    });

    // --- GET ROWS ---
    CROW_ROUTE(app, "/get_rows").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string db_file = body.value("db_file", "");
            std::string table = body.value("table", "");
            if (user_id.empty() || db_file.empty() || table.empty())
                return error_resp("Missing required fields");

            std::string sql = "SELECT * FROM " + table;
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

    // --- RENAME DB ---
    CROW_ROUTE(app, "/rename_db").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string old_name = body.value("old_name", "");
            std::string new_name = body.value("new_name", "");
            if (user_id.empty() || old_name.empty() || new_name.empty())
                return error_resp("Missing user_id or db file names");

            std::string dir = "db_root/" + user_id;
            fs::create_directories(dir);
            std::string old_path = dir + "/" + old_name;
            std::string new_path = dir + "/" + new_name;

            if (!fs::exists(old_path)) return error_resp("Database not found", 404);
            fs::rename(old_path, new_path);

            json res;
            res["success"] = true;
            res["new_path"] = new_path;
            return crow::response(res.dump());
        } catch (const std::exception& e) {
            return error_resp(std::string("Exception: ") + e.what(), 500);
        }
    });

    // --- DELETE DB ---
    CROW_ROUTE(app, "/delete_db").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string db_file = body.value("db_file", "");
            if (user_id.empty() || db_file.empty())
                return error_resp("Missing user_id or db_file");

            std::string path = get_db_path(user_id, db_file);
            if (!fs::exists(path)) return error_resp("Database not found", 404);

            fs::remove(path);

            json res;
            res["success"] = true;
            return crow::response(res.dump());
        } catch (const std::exception& e) {
            return error_resp(std::string("Exception: ") + e.what(), 500);
        }
    });

    // --- DOWNLOAD DB ---
    CROW_ROUTE(app, "/download_db").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        if (!user_id || !db_file)
            return error_resp("Missing user_id or db_file");

        std::string path = get_db_path(user_id, db_file);
        if (!fs::exists(path)) return error_resp("Database file not found", 404);

        std::ifstream in(path, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();

        crow::response res;
        res.set_header("Content-Type", "application/octet-stream");
        res.set_header("Content-Disposition", std::string("attachment; filename=") + db_file);
        res.write(ss.str());
        return res;
    });

    // --- DB STATS ---
    CROW_ROUTE(app, "/db_stats").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        if (!user_id || !db_file)
            return error_resp("Missing user_id or db_file");

        std::string path = get_db_path(user_id, db_file);
        if (!fs::exists(path)) return error_resp("File not found", 404);

        json res;
        res["size_bytes"] = fs::file_size(path);
        res["last_modified"] = std::chrono::duration_cast<std::chrono::seconds>(fs::last_write_time(path).time_since_epoch()).count();
        return crow::response(res.dump());
    });
    // --- VALIDATE SQL ---
    CROW_ROUTE(app, "/validate_sql").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string sql = body.value("sql", "");
            if (sql.empty()) return error_resp("Missing SQL to validate");

            bool is_select = sql.find("select") == 0 || sql.find("SELECT") == 0;
            bool is_dml = sql.find("insert") == 0 || sql.find("update") == 0 || sql.find("delete") == 0;
            json res;
            res["type"] = is_select ? "SELECT" : (is_dml ? "DML" : "UNKNOWN");
            res["valid"] = true;
            return crow::response(res.dump());
        } catch (...) {
            return error_resp("Invalid JSON or SQL");
        }
    });

    // --- TABLE PREVIEW ---
    CROW_ROUTE(app, "/table_preview").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        auto table = req.url_params.get("table");
        int limit = req.url_params.get("limit") ? std::stoi(req.url_params.get("limit")) : 10;
        if (!user_id || !db_file || !table)
            return error_resp("Missing parameters");

        std::string path = get_db_path(user_id, db_file);
        json err;
        sqlite3* db = open_db(path, err);
        if (!db) return crow::response(500, err.dump());

        std::string sql = "SELECT * FROM " + std::string(table) + " LIMIT " + std::to_string(limit);
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
        res["preview"] = rows;
        return crow::response(res.dump());
    });

    // --- COLUMN INFO ---
    CROW_ROUTE(app, "/column_info").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        auto table = req.url_params.get("table");
        if (!user_id || !db_file || !table)
            return error_resp("Missing parameters");

        std::string path = get_db_path(user_id, db_file);
        json err;
        sqlite3* db = open_db(path, err);
        if (!db) return crow::response(500, err.dump());

        std::vector<json> info;
        std::string sql = "PRAGMA table_info(" + std::string(table) + ")";
        char* errMsg = nullptr;

        auto cb = [](void* data, int argc, char** argv, char** colNames) {
            auto* list = static_cast<std::vector<json>*>(data);
            json col;
            for (int i = 0; i < argc; ++i)
                col[colNames[i]] = argv[i] ? argv[i] : nullptr;
            list->push_back(col);
            return 0;
        };

        int rc = sqlite3_exec(db, sql.c_str(), cb, &info, &errMsg);
        sqlite3_close(db);
        if (rc != SQLITE_OK) {
            std::string msg = errMsg ? errMsg : "SQL error";
            sqlite3_free(errMsg);
            return error_resp(msg);
        }

        json res;
        res["columns"] = info;
        return crow::response(res.dump());
    });

    // --- SEARCH (simple filter query builder) ---
    CROW_ROUTE(app, "/search").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string db_file = body.value("db_file", "");
            std::string table = body.value("table", "");
            json filters = body.value("filters", json::array());

            if (user_id.empty() || db_file.empty() || table.empty())
                return error_resp("Missing required fields");

            std::string sql = "SELECT * FROM " + table;
            if (!filters.empty()) {
                sql += " WHERE ";
                bool first = true;
                for (const auto& cond : filters) {
                    if (!first) sql += " AND ";
                    sql += cond["column"].get<std::string>() + " " + cond["op"].get<std::string>() + " '" + cond["value"].get<std::string>() + "'";
                    first = false;
                }
            }

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

    return app.port(4000).multithreaded().run(), 0;
}
