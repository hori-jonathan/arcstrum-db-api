#define CROW_MAIN
#define ASIO_STANDALONE
#include "crow.h"
#include <sqlite3.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ====================
// CORS Middleware
// ====================

struct CORS {
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context&) {
        /*res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.add_header("Access-Control-Allow-Credentials", "true");
        if (req.method == "OPTIONS"_method) {
            res.code = 204;
            res.end();
        }*/
    }
    void after_handle(crow::request&, crow::response& res, context&) {
        /*res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.add_header("Access-Control-Allow-Credentials", "true");*/
    }
};

// ====================
// User-Folder Utilities
// ====================

std::string get_user_db_path(const std::string& user_id, const std::string& dbfile) {
    std::string base = "db_root";
    std::string folder = base + "/" + user_id;
    fs::create_directories(folder);
    return folder + "/" + dbfile;
}

std::vector<std::string> list_user_dbfiles(const std::string& user_id) {
    std::vector<std::string> dbs;
    std::string folder = "db_root/" + user_id;
    if (!fs::exists(folder)) return dbs;
    for (auto& entry : fs::directory_iterator(folder)) {
        if (entry.is_regular_file()) dbs.push_back(entry.path().filename().string());
    }
    return dbs;
}

// Compose a unique key for the manager's servers map
std::string server_key(const std::string& user_id, const std::string& dbfile) {
    return user_id + "/" + dbfile;
}

// ====================
// Helper Functions
// ====================

static int select_callback(void* data, int argc, char** argv, char** azColName) {
    auto* rows = static_cast<std::vector<json>*>(data);
    json row;
    for (int i = 0; i < argc; i++) {
        row[azColName[i]] = argv[i] ? argv[i] : nullptr;
    }
    rows->push_back(row);
    return 0;
}

// For non-select (exec) statements, just record affected rows
static int count_callback(void* data, int, char**, char**) {
    int* count = static_cast<int*>(data);
    (*count)++;
    return 0;
}

crow::response error_resp(const std::string& msg, int code = 400) {
    json response;
    response["error"] = msg;
    return crow::response{code, response.dump()};
}

// Helper for opening DB
sqlite3* open_db(const char* dbfile, json& response) {
    sqlite3* db = nullptr;
    int rc = sqlite3_open(dbfile, &db);
    if (rc) {
        response["error"] = std::string("Can't open DB: ") + sqlite3_errmsg(db);
        if (db) sqlite3_close(db);
        return nullptr;
    }
    return db;
}

int main() {
    crow::SimpleApp app;

    const char* dbfile = "mydb.sqlite";

    // Health check
    CROW_ROUTE(app, "/")([] {
        return R"({"status":"db-api up and running with SQLite!"})";
    });

    // /query (POST, SELECT only)
    CROW_ROUTE(app, "/query").methods(crow::HTTPMethod::Post)(
        [dbfile](const crow::request& req) {
            json response;
            try {
                auto body = json::parse(req.body);
                std::string sql = body.value("sql", "");
                if (sql.empty() || (sql.substr(0, 6) != "SELECT" && sql.substr(0, 6) != "select")) {
                    return error_resp("Only SELECT statements are allowed.");
                }
                sqlite3* db = open_db(dbfile, response);
                if (!db) return crow::response{500, response.dump()};

                std::vector<json> rows;
                char* errMsg = nullptr;
                int rc = sqlite3_exec(db, sql.c_str(), select_callback, &rows, &errMsg);
                if (rc != SQLITE_OK) {
                    auto msg = std::string("SQL error: ") + (errMsg ? errMsg : "unknown");
                    if (errMsg) sqlite3_free(errMsg);
                    sqlite3_close(db);
                    return error_resp(msg);
                }

                response["rows"] = rows;
                sqlite3_close(db);
                return crow::response{response.dump()};
            } catch (const std::exception& ex) {
                return error_resp("Exception: " + std::string(ex.what()), 500);
            }
        });

    // /exec (POST, any SQL)
    CROW_ROUTE(app, "/exec").methods(crow::HTTPMethod::Post)(
        [dbfile](const crow::request& req) {
            json response;
            try {
                auto body = json::parse(req.body);
                std::string sql = body.value("sql", "");
                if (sql.empty()) return error_resp("Missing 'sql'.");

                sqlite3* db = open_db(dbfile, response);
                if (!db) return crow::response{500, response.dump()};

                char* errMsg = nullptr;
                int affected = 0;
                int rc = sqlite3_exec(db, sql.c_str(), count_callback, &affected, &errMsg);
                if (rc != SQLITE_OK) {
                    auto msg = std::string("SQL error: ") + (errMsg ? errMsg : "unknown");
                    if (errMsg) sqlite3_free(errMsg);
                    sqlite3_close(db);
                    return error_resp(msg);
                }

                response["success"] = true;
                response["affected_rows"] = affected;
                sqlite3_close(db);
                return crow::response{response.dump()};
            } catch (const std::exception& ex) {
                return error_resp("Exception: " + std::string(ex.what()), 500);
            }
        });

    // /insert (POST, table + values)
    CROW_ROUTE(app, "/insert").methods(crow::HTTPMethod::Post)(
        [dbfile](const crow::request& req) {
            json response;
            try {
                auto body = json::parse(req.body);
                std::string table = body.value("table", "");
                json values = body.value("values", json::object());
                if (table.empty() || !values.is_object()) return error_resp("Missing table or values.");

                std::string fields, vals, q;
                for (auto it = values.begin(); it != values.end(); ++it) {
                    if (it != values.begin()) { fields += ","; vals += ","; }
                    fields += it.key();
                    vals += "'" + std::string(it.value().dump()).substr(1, it.value().dump().size() - 2) + "'";
                }
                q = "INSERT INTO " + table + " (" + fields + ") VALUES (" + vals + ");";

                sqlite3* db = open_db(dbfile, response);
                if (!db) return crow::response{500, response.dump()};

                char* errMsg = nullptr;
                int rc = sqlite3_exec(db, q.c_str(), nullptr, nullptr, &errMsg);
                if (rc != SQLITE_OK) {
                    auto msg = std::string("SQL error: ") + (errMsg ? errMsg : "unknown");
                    if (errMsg) sqlite3_free(errMsg);
                    sqlite3_close(db);
                    return error_resp(msg);
                }

                response["success"] = true;
                sqlite3_close(db);
                return crow::response{response.dump()};
            } catch (const std::exception& ex) {
                return error_resp("Exception: " + std::string(ex.what()), 500);
            }
        });

    // /update (POST, table + values + where)
    CROW_ROUTE(app, "/update").methods(crow::HTTPMethod::Post)(
        [dbfile](const crow::request& req) {
            json response;
            try {
                auto body = json::parse(req.body);
                std::string table = body.value("table", "");
                json values = body.value("values", json::object());
                std::string where = body.value("where", "");
                if (table.empty() || !values.is_object() || where.empty()) return error_resp("Missing table, values, or where.");

                std::string sets;
                for (auto it = values.begin(); it != values.end(); ++it) {
                    if (it != values.begin()) sets += ",";
                    sets += it.key() + "='" + std::string(it.value().dump()).substr(1, it.value().dump().size() - 2) + "'";
                }
                std::string q = "UPDATE " + table + " SET " + sets + " WHERE " + where + ";";

                sqlite3* db = open_db(dbfile, response);
                if (!db) return crow::response{500, response.dump()};

                char* errMsg = nullptr;
                int rc = sqlite3_exec(db, q.c_str(), nullptr, nullptr, &errMsg);
                if (rc != SQLITE_OK) {
                    auto msg = std::string("SQL error: ") + (errMsg ? errMsg : "unknown");
                    if (errMsg) sqlite3_free(errMsg);
                    sqlite3_close(db);
                    return error_resp(msg);
                }

                response["success"] = true;
                sqlite3_close(db);
                return crow::response{response.dump()};
            } catch (const std::exception& ex) {
                return error_resp("Exception: " + std::string(ex.what()), 500);
            }
        });

    // /delete (POST, table + where)
    CROW_ROUTE(app, "/delete").methods(crow::HTTPMethod::Post)(
        [dbfile](const crow::request& req) {
            json response;
            try {
                auto body = json::parse(req.body);
                std::string table = body.value("table", "");
                std::string where = body.value("where", "");
                if (table.empty() || where.empty()) return error_resp("Missing table or where.");

                std::string q = "DELETE FROM " + table + " WHERE " + where + ";";

                sqlite3* db = open_db(dbfile, response);
                if (!db) return crow::response{500, response.dump()};

                char* errMsg = nullptr;
                int rc = sqlite3_exec(db, q.c_str(), nullptr, nullptr, &errMsg);
                if (rc != SQLITE_OK) {
                    auto msg = std::string("SQL error: ") + (errMsg ? errMsg : "unknown");
                    if (errMsg) sqlite3_free(errMsg);
                    sqlite3_close(db);
                    return error_resp(msg);
                }

                response["success"] = true;
                sqlite3_close(db);
                return crow::response{response.dump()};
            } catch (const std::exception& ex) {
                return error_resp("Exception: " + std::string(ex.what()), 500);
            }
        });

    // /tables (GET)
    CROW_ROUTE(app, "/tables").methods(crow::HTTPMethod::Get)([dbfile]() {
        json response;
        sqlite3* db = nullptr;
        db = open_db(dbfile, response);
        if (!db) return crow::response{500, response.dump()};
        std::vector<json> tables;
        char* errMsg = nullptr;
        auto cb = [](void* data, int argc, char** argv, char**) -> int {
            auto* arr = static_cast<std::vector<json>*>(data);
            if (argc > 0) arr->push_back(argv[0] ? argv[0] : nullptr);
            return 0;
        };
        std::string sql = "SELECT name FROM sqlite_master WHERE type='table';";
        int rc = sqlite3_exec(db, sql.c_str(), cb, &tables, &errMsg);
        if (rc != SQLITE_OK) {
            auto msg = std::string("SQL error: ") + (errMsg ? errMsg : "unknown");
            if (errMsg) sqlite3_free(errMsg);
            sqlite3_close(db);
            return error_resp(msg);
        }
        response["tables"] = tables;
        sqlite3_close(db);
        return crow::response{response.dump()};
    });

    // /schema (GET)
    CROW_ROUTE(app, "/schema").methods(crow::HTTPMethod::Get)([dbfile]() {
        json response;
        sqlite3* db = nullptr;
        db = open_db(dbfile, response);
        if (!db) return crow::response{500, response.dump()};
        std::vector<json> schemas;
        char* errMsg = nullptr;
        auto cb = [](void* data, int argc, char** argv, char** azColName) -> int {
            auto* arr = static_cast<std::vector<json>*>(data);
            json row;
            for (int i = 0; i < argc; i++) {
                row[azColName[i]] = argv[i] ? argv[i] : nullptr;
            }
            arr->push_back(row);
            return 0;
        };
        std::string sql = "SELECT name, sql FROM sqlite_master WHERE type='table';";
        int rc = sqlite3_exec(db, sql.c_str(), cb, &schemas, &errMsg);
        if (rc != SQLITE_OK) {
            auto msg = std::string("SQL error: ") + (errMsg ? errMsg : "unknown");
            if (errMsg) sqlite3_free(errMsg);
            sqlite3_close(db);
            return error_resp(msg);
        }
        response["schemas"] = schemas;
        sqlite3_close(db);
        return crow::response{response.dump()};
    });

    app.port(4000).multithreaded().run();
}

