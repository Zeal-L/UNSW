#ifndef COMP6771_RETHROW_HPP
#define COMP6771_RETHROW_HPP

#include <set>
#include <string>

class db_conn {
    /**
     * @brief A blacklist of users who are not allowed to make connections.
     * Currently, there is a single username who cannot login: hsmith
     */
    static const std::set<std::string> blacklist_;
public:
    /**
     *  @brief Default Constructor.
     * No need to modify this.
     */
    db_conn() noexcept = default;

    /**
     * @brief Attempts to make a connection given a uname and pwd.
     *
     * If the uname is not part of the blacklist, and pword is at least 8 characters,
     * the connection is successfully established (i.e. active_ becomes true).
     * Once a connection is established, any further calls to this function have no effect.
     * All calls to this function, even calls that result in an exception being thrown, count as attempts.
     *
     * Throws exceptions in the cases and order given below.
     *
     * @throws std::domain_error: if uname is part of the blacklist,
     *         throws a std::domain_error with message: <uname> is not allowed to login.
     * @throws std::runtime_error: every 2nd attempt, the computer malfunctions and throws a std::runtime_error with message:
     *         HeLp ;_; c0mpu73R c@ann0T c0mPut3 0w0
     *
     * @param uname - the uname to login / make a connection.
     * @param pword - the password of the user.
     */
    auto try_connect(const std::string &uname, const std::string &pword) -> void;

    /**
     * @brief Returns the connection status of this db_conn.
     *
     * @return bool - true if this connection is active, false otherwise.
     */
    auto is_active() const -> bool;
private:
    int n_attempts_;
    bool active_;
};

/**
 * @brief Attempts to make a connection to db with uname and pwd.
 *
 * If any exceptions occur, rethrows them as std::strings.
 *
 * @param db - the db to make a connection to.
 * @param uname - the uname to login / make a connection.
 * @param pword - the password of the user.
 */
auto make_connection(db_conn &db, const std::string &uname, const std::string &pword) -> void;

#endif // COMP6771_RETHROW_HPP
