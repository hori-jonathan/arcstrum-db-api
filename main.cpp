#define CROW_MAIN
#define ASIO_STANDALONE
#include "crow.h"
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <algorithm>

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
        std::string key = colNames[i] ? colNames[i] : ("col" + std::to_string(i));
        const char* val = argv[i] ? argv[i] : "";
        row[key] = val;
    }
    rows->push_back(row);
    return 0;
}

static int safe_column_info_cb(void* data, int argc, char** argv, char** colNames) {
    auto* list = static_cast<std::vector<json>*>(data);
    json col;
    for (int i = 0; i < argc; ++i) {
        std::string key = colNames[i] ? colNames[i] : ("col" + std::to_string(i));
        const char* val = argv[i] ? argv[i] : "";
        col[key] = val;
    }
    list->push_back(col);
    return 0;
}

long long get_last_modified_safe(const fs::path& path) {
    auto ftime = fs::last_write_time(path);
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
    );
    return std::chrono::duration_cast<std::chrono::seconds>(sctp.time_since_epoch()).count();
}

std::string get_meta_path(const std::string& user_id, const std::string& db_file) {
    return "db_root/" + user_id + "/" + db_file + ".meta.json";
}

void log_status(
    const std::string& user_id,
    const std::string& db_file,
    const std::string& endpoint,
    int status_code,
    const json& meta = {}
) {
    try {
        std::string log_dir = "status/" + user_id;
        fs::create_directories(log_dir);

        // Optional: sanitize db_file name to prevent slashes
        std::string safe_name = db_file;
        std::replace(safe_name.begin(), safe_name.end(), '/', '_');

        std::string log_path = log_dir + "/" + safe_name + ".jsonl";

        json entry = {
            {"timestamp", std::time(nullptr)},
            {"endpoint", endpoint},
            {"status", status_code},
            {"db", db_file},
            {"meta", meta}
        };

        std::ofstream out(log_path, std::ios::app);
        out << entry.dump() << "\n";
    } catch (...) {
        std::cerr << "[log_status] Failed to log " << endpoint << " for " << user_id << "/" << db_file << "\n";
    }
}

int main() {
    crow::App<CORS> app;

    CROW_ROUTE(app, "/")([] {
        return R"({"status":"db-api online"})";
    });

    CROW_ROUTE(app, "/list").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            if (user_id.empty()) return error_resp("Missing user_id");

            std::string dir = "db_root/" + user_id;
            std::vector<std::string> files;

            if (fs::exists(dir)) {
                for (const auto& entry : fs::directory_iterator(dir)) {
                    if (entry.is_regular_file())
                        files.push_back(entry.path().filename().string());
                }
            }

            log_status(user_id, "__all__", "/list", 200, {{"file_count", files.size()}});
            json res;
            res["files"] = files;
            return crow::response(res.dump());
        } catch (const std::exception& e) {
            return error_resp(std::string("Exception: ") + e.what(), 500);
        }
    });

    CROW_ROUTE(app, "/query").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];
            std::string sql = body["sql"];

            json err;
            sqlite3* db = open_db(get_db_path(user_id, db_file), err);
            if (!db) {
                log_status(user_id, db_file, "/query", 500, {{"sql", sql}});
                return crow::response(500, err.dump());
            }

            std::vector<json> rows;
            char* errMsg = nullptr;
            int rc = sqlite3_exec(db, sql.c_str(), select_callback, &rows, &errMsg);
            sqlite3_close(db);

            if (rc != SQLITE_OK) {
                std::string msg = errMsg ? errMsg : "SQL error";
                log_status(user_id, db_file, "/query", 500, {{"sql", sql}});
                return error_resp(msg);
            }

            log_status(user_id, db_file, "/query", 200, {{"sql", sql}, {"rows", rows.size()}});
            return crow::response(json({{"rows", rows}}).dump());
        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });

    CROW_ROUTE(app, "/create_database").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string db_file = body.value("db_file", "");
            if (user_id.empty() || db_file.empty()) return error_resp("Missing user_id or db_file");

            std::string path = get_db_path(user_id, db_file);
            fs::create_directories("db_root/" + user_id);

            std::ofstream new_db(path);
            if (!new_db) return error_resp("Failed to create DB file", 500);
            new_db.close();

            json dummy_err;
            sqlite3* db = open_db(path, dummy_err);
            if (!db) return error_resp("SQLite init failed", 500);
            sqlite3_close(db);

            log_status(user_id, db_file, "/db/create_database", 200);
            return crow::response(R"({"success":true})");
        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });

    CROW_ROUTE(app, "/exec").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];
            std::string sql = body["sql"];

            json err;
            sqlite3* db = open_db(get_db_path(user_id, db_file), err);
            if (!db) {
                log_status(user_id, db_file, "/exec", 500, {{"sql", sql}});
                return crow::response(500, err.dump());
            }

            char* errMsg = nullptr;
            int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
            sqlite3_close(db);

            if (rc != SQLITE_OK) {
                std::string msg = errMsg ? errMsg : "SQL error";
                log_status(user_id, db_file, "/exec", 500, {{"sql", sql}});
                return error_resp(msg);
            }

            log_status(user_id, db_file, "/exec", 200, {{"sql", sql}});
            return crow::response(R"({"success":true})");
        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });

    CROW_ROUTE(app, "/insert_row").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];
            std::string table = body["table"];
            json row = body["row"];

            std::string sql = "INSERT INTO " + table + " (";
            std::string values = "VALUES (";
            bool first = true;
            for (auto it = row.begin(); it != row.end(); ++it) {
                if (!first) {
                    sql += ", ";
                    values += ", ";
                }
                sql += it.key();
                values += "'" + it.value().get<std::string>() + "'";
                first = false;
            }
            sql += ") " + values + ")";

            json err;
            sqlite3* db = open_db(get_db_path(user_id, db_file), err);
            if (!db) {
                log_status(user_id, db_file, "/insert_row", 500, {{"table", table}});
                return crow::response(500, err.dump());
            }

            char* errMsg = nullptr;
            int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
            sqlite3_close(db);

            if (rc != SQLITE_OK) {
                std::string msg = errMsg ? errMsg : "SQL error";
                log_status(user_id, db_file, "/insert_row", 500, {{"table", table}});
                return error_resp(msg);
            }

            log_status(user_id, db_file, "/insert_row", 200, {{"table", table}});
            return crow::response(R"({"success":true})");
        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });

    CROW_ROUTE(app, "/rename_db").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string old_name = body["old_name"];
            std::string new_name = body["new_name"];

            std::string dir = "db_root/" + user_id;
            fs::create_directories(dir);
            std::string old_path = dir + "/" + old_name;
            std::string new_path = dir + "/" + new_name;

            if (!fs::exists(old_path)) {
                log_status(user_id, old_name, "/rename_db", 404);
                return error_resp("Database not found", 404);
            }

            fs::rename(old_path, new_path);
            log_status(user_id, new_name, "/rename_db", 200, {{"old", old_name}, {"new", new_name}});

            return crow::response(json({{"success", true}, {"new_path", new_path}}).dump());
        } catch (const std::exception& e) {
            return error_resp(std::string("Exception: ") + e.what(), 500);
        }
    });

    CROW_ROUTE(app, "/delete_db").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];

            std::string path = get_db_path(user_id, db_file);
            if (!fs::exists(path)) {
                log_status(user_id, db_file, "/delete_db", 404);
                return error_resp("Database not found", 404);
            }

            fs::remove(path);
            log_status(user_id, db_file, "/delete_db", 200);
            return crow::response(R"({"success":true})");
        } catch (const std::exception& e) {
            return error_resp(std::string("Exception: ") + e.what(), 500);
        }
    });

    CROW_ROUTE(app, "/db_stats").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        if (!user_id || !db_file) return error_resp("Missing user_id or db_file");

        std::string path = get_db_path(user_id, db_file);
        if (!fs::exists(path)) return error_resp("File not found", 404);

        json res;
        res["size_bytes"] = fs::file_size(path);
        res["last_modified"] = get_last_modified_safe(path);

        log_status(user_id, db_file, "/db_stats", 200, res);
        return crow::response(res.dump());
    });

    CROW_ROUTE(app, "/download_db").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        if (!user_id || !db_file) return error_resp("Missing user_id or db_file");

        std::string path = get_db_path(user_id, db_file);
        if (!fs::exists(path)) return error_resp("Database file not found", 404);

        std::ifstream in(path, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();

        log_status(user_id, db_file, "/download_db", 200);
        crow::response res;
        res.set_header("Content-Type", "application/octet-stream");
        res.set_header("Content-Disposition", std::string("attachment; filename=") + db_file);
        res.write(ss.str());
        return res;
    });

    CROW_ROUTE(app, "/validate_sql").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string sql = body["sql"];
            std::string type = "UNKNOWN";

            if (sql.find("select") == 0 || sql.find("SELECT") == 0) type = "SELECT";
            else if (sql.find("insert") == 0 || sql.find("update") == 0 || sql.find("delete") == 0) type = "DML";

            json res = {{"valid", true}, {"type", type}};
            log_status("__system__", "__sql__", "/validate_sql", 200, res);
            return crow::response(res.dump());
        } catch (...) {
            return error_resp("Invalid JSON or SQL");
        }
    });

    CROW_ROUTE(app, "/tables").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");

        if (!user_id || !db_file) return error_resp("Missing user_id or db_file");

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
            return error_resp(msg);
        }

        log_status(user_id, db_file, "/tables", 200, {{"count", tables.size()}});
        return crow::response(json({{"tables", tables}}).dump());
    });
    CROW_ROUTE(app, "/get_rows").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];
            std::string table = body["table"];

            std::string sql = "SELECT * FROM " + table;
            json err;
            sqlite3* db = open_db(get_db_path(user_id, db_file), err);
            if (!db) return crow::response(500, err.dump());

            std::vector<json> rows;
            char* errMsg = nullptr;
            int rc = sqlite3_exec(db, sql.c_str(), select_callback, &rows, &errMsg);
            sqlite3_close(db);

            if (rc != SQLITE_OK) {
                std::string msg = errMsg ? errMsg : "SQL error";
                return error_resp(msg);
            }

            log_status(user_id, db_file, "/get_rows", 200, {{"table", table}, {"rows", rows.size()}});
            return crow::response(json({{"rows", rows}}).dump());
        } catch (...) {
            return error_resp("Invalid JSON", 400);
        }
    });
    CROW_ROUTE(app, "/column_info").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        auto table = req.url_params.get("table");
        if (!user_id || !db_file || !table) return error_resp("Missing parameters");

        json err;
        sqlite3* db = open_db(get_db_path(user_id, db_file), err);
        if (!db) return crow::response(500, err.dump());

        std::vector<json> cols;
        std::string sql = "PRAGMA table_info(" + std::string(table) + ")";
        char* errMsg = nullptr;

        int rc = sqlite3_exec(db, sql.c_str(), safe_column_info_cb, &cols, &errMsg);
        sqlite3_close(db);

        if (rc != SQLITE_OK) {
            std::string msg = errMsg ? errMsg : "SQL error";
            return error_resp(msg);
        }

        log_status(user_id, db_file, "/column_info", 200, {{"table", table}, {"columns", cols.size()}});
        return crow::response(json({{"columns", cols}}).dump());
    });
    CROW_ROUTE(app, "/table_preview").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        auto table = req.url_params.get("table");
        int limit = req.url_params.get("limit") ? std::stoi(req.url_params.get("limit")) : 10;
        if (!user_id || !db_file || !table) return error_resp("Missing parameters");

        json err;
        sqlite3* db = open_db(get_db_path(user_id, db_file), err);
        if (!db) return crow::response(500, err.dump());

        std::string sql = "SELECT * FROM " + std::string(table) + " LIMIT " + std::to_string(limit);
        std::vector<json> rows;
        char* errMsg = nullptr;

        int rc = sqlite3_exec(db, sql.c_str(), select_callback, &rows, &errMsg);
        sqlite3_close(db);

        if (rc != SQLITE_OK) {
            std::string msg = errMsg ? errMsg : "SQL error";
            return error_resp(msg);
        }

        log_status(user_id, db_file, "/table_preview", 200, {{"table", table}, {"rows", rows.size()}});
        return crow::response(json({{"preview", rows}}).dump());
    });
    CROW_ROUTE(app, "/search").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];
            std::string table = body["table"];
            json filters = body["filters"];

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

            json err;
            sqlite3* db = open_db(get_db_path(user_id, db_file), err);
            if (!db) return crow::response(500, err.dump());

            std::vector<json> rows;
            char* errMsg = nullptr;
            int rc = sqlite3_exec(db, sql.c_str(), select_callback, &rows, &errMsg);
            sqlite3_close(db);

            if (rc != SQLITE_OK) {
                std::string msg = errMsg ? errMsg : "SQL error";
                return error_resp(msg);
            }

            log_status(user_id, db_file, "/search", 200, {{"table", table}, {"rows", rows.size()}});
            return crow::response(json({{"rows", rows}}).dump());
        } catch (...) {
            return error_resp("Invalid JSON", 400);
        }
    });

    CROW_ROUTE(app, "/usage_analytics").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        if (!user_id) return error_resp("Missing user_id");

        std::string user_dir = std::string("status/") + user_id;
        if (!fs::exists(user_dir)) return error_resp("User has no status data", 404);

        std::map<std::string, std::map<std::string, int>> usage_per_db;

        for (const auto& entry : fs::directory_iterator(user_dir)) {
            if (!entry.is_regular_file()) continue;
            std::string db_file = entry.path().filename().string();

            std::ifstream in(entry.path());
            std::string line;
            while (std::getline(in, line)) {
                try {
                    auto json_entry = json::parse(line);
                    long timestamp = json_entry.value("timestamp", 0);
                    std::time_t time = static_cast<std::time_t>(timestamp);
                    std::tm* tm_ptr = std::gmtime(&time);

                    // Format: YYYY-MM-DD
                    char buf[16];
                    std::strftime(buf, sizeof(buf), "%Y-%m-%d", tm_ptr);
                    std::string day = std::string(buf);

                    usage_per_db[db_file][day]++;
                } catch (...) {}
            }
        }

        return crow::response(json(usage_per_db).dump());
    });

    CROW_ROUTE(app, "/delete_row").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];
            std::string table = body["table"];
            json row = body["row"];

            if (row.empty()) return error_resp("Missing row data");

            json err;
            sqlite3* db = open_db(get_db_path(user_id, db_file), err);
            if (!db) return crow::response(500, err.dump());

            // Construct DELETE statement based on row's column values
            std::string sql = "DELETE FROM " + table + " WHERE ";
            bool first = true;
            for (auto it = row.begin(); it != row.end(); ++it) {
                if (!first) sql += " AND ";
                sql += it.key() + " = '" + it.value().get<std::string>() + "'";
                first = false;
            }

            char* errMsg = nullptr;
            int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
            sqlite3_close(db);

            if (rc != SQLITE_OK) {
                std::string msg = errMsg ? errMsg : "SQL error";
                log_status(user_id, db_file, "/delete_row", 500, {{"sql", sql}});
                return error_resp(msg);
            }

            log_status(user_id, db_file, "/delete_row", 200, {{"sql", sql}});
            return crow::response(R"({"success":true})");
        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });

    CROW_ROUTE(app, "/table_schema").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");
        auto table = req.url_params.get("table");

        if (!user_id || !db_file || !table)
            return error_resp("Missing required parameters");

        json err;
        sqlite3* db = open_db(get_db_path(user_id, db_file), err);
        if (!db) return crow::response(500, err.dump());

        std::vector<json> cols;
        std::string sql = "PRAGMA table_info('" + std::string(table) + "')";
        char* errMsg = nullptr;

        int rc = sqlite3_exec(db, sql.c_str(), safe_column_info_cb, &cols, &errMsg);
        sqlite3_close(db);

        if (rc != SQLITE_OK) {
            std::string msg = errMsg ? errMsg : "SQL error";
            return error_resp(msg);
        }

        log_status(user_id, db_file, "/table_schema", 200, {{"table", table}, {"columns", cols.size()}});
        return crow::response(json({{"columns", cols}}).dump());
    });

    CROW_ROUTE(app, "/status_history").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");

        if (!user_id || !db_file)
            return error_resp("Missing user_id or db_file");

        std::string safe_name = db_file;
        std::replace(safe_name.begin(), safe_name.end(), '/', '_');

        std::string path = "status/" + std::string(user_id) + "/" + safe_name + ".jsonl";
        if (!fs::exists(path)) return error_resp("Status log not found", 404);

        std::ifstream in(path);
        std::string line;
        std::vector<json> entries;
        while (std::getline(in, line)) {
            try {
                entries.push_back(json::parse(line));
            } catch (...) {}
        }

        return crow::response(json({{"history", entries}}).dump());
    });

    CROW_ROUTE(app, "/status_history").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_filter = body.value("user_id", "");
            std::string db_filter = body.value("db_file", "");
            std::string endpoint_filter = body.value("endpoint", "");
            long since = body.value("since", 0L);

            std::vector<json> results;

            for (const auto& user_entry : fs::directory_iterator("status")) {
                if (!user_entry.is_directory()) continue;
                std::string user_id = user_entry.path().filename().string();
                if (!user_filter.empty() && user_id != user_filter) continue;

                for (const auto& file_entry : fs::directory_iterator(user_entry.path())) {
                    if (!file_entry.is_regular_file()) continue;
                    std::string db_file = file_entry.path().filename().string();
                    if (!db_filter.empty() && db_file != db_filter) continue;

                    std::ifstream in(file_entry.path());
                    std::string line;
                    while (std::getline(in, line)) {
                        try {
                            auto entry = json::parse(line);
                            if (since > 0 && entry["timestamp"].get<long>() < since) continue;
                            if (!endpoint_filter.empty() && entry["endpoint"] != endpoint_filter) continue;
                            results.push_back(entry);
                        } catch (...) {}
                    }
                }
            }

            std::sort(results.begin(), results.end(), [](const json& a, const json& b) {
                return a["timestamp"].get<long>() > b["timestamp"].get<long>();
            });

            return crow::response(json({{"history", results}}).dump());

        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });

    CROW_ROUTE(app, "/drop_table").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];
            std::string table = body["table"];

            std::string sql = "DROP TABLE IF EXISTS " + table;

            json err;
            sqlite3* db = open_db(get_db_path(user_id, db_file), err);
            if (!db) {
                log_status(user_id, db_file, "/drop_table", 500, {{"table", table}});
                return crow::response(500, err.dump());
            }

            char* errMsg = nullptr;
            int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
            sqlite3_close(db);

            if (rc != SQLITE_OK) {
                std::string msg = errMsg ? errMsg : "SQL error";
                log_status(user_id, db_file, "/drop_table", 500, {{"table", table}});
                return error_resp(msg);
            }

            log_status(user_id, db_file, "/drop_table", 200, {{"table", table}});
            return crow::response(R"({"success":true})");
        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });
    CROW_ROUTE(app, "/get_metadata").methods("GET"_method)([](const crow::request& req) {
        auto user_id = req.url_params.get("user_id");
        auto db_file = req.url_params.get("db_file");

        if (!user_id || !db_file)
            return error_resp("Missing user_id or db_file");

        std::string meta_path = get_meta_path(user_id, db_file);
        if (!fs::exists(meta_path))
            return error_resp("Metadata file not found", 404);

        std::ifstream in(meta_path);
        if (!in) return error_resp("Failed to read metadata", 500);

        json meta;
        try {
            in >> meta;
        } catch (...) {
            return error_resp("Failed to parse metadata", 500);
        }

        return crow::response(meta.dump());
    });
    CROW_ROUTE(app, "/update_metadata").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];
            json metadata = body["metadata"];

            std::string meta_path = get_meta_path(user_id, db_file);
            fs::create_directories("db_root/" + user_id);

            std::ofstream out(meta_path);
            if (!out) return error_resp("Failed to write metadata", 500);
            out << metadata.dump(2);  // Pretty print

            log_status(user_id, db_file, "/update_metadata", 200, metadata);
            return crow::response(R"({"success":true})");
        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });
    CROW_ROUTE(app, "/delete_metadata").methods("POST"_method)([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            std::string user_id = body["user_id"];
            std::string db_file = body["db_file"];

            std::string meta_path = get_meta_path(user_id, db_file);
            if (!fs::exists(meta_path)) {
                log_status(user_id, db_file, "/delete_metadata", 404);
                return error_resp("Metadata not found", 404);
            }

            fs::remove(meta_path);
            log_status(user_id, db_file, "/delete_metadata", 200);
            return crow::response(R"({"success":true})");
        } catch (...) {
            return error_resp("Invalid JSON or request", 400);
        }
    });

    return app.port(4000).multithreaded().run(), 0;
}

