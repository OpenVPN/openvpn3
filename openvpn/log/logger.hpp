//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2022 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#pragma once

namespace openvpn::logging {

/** log message level with the highest priority. Critical messages that should always be shown are in this category */
constexpr int LOG_LEVEL_ERROR = 0;
/** log message level with high/normal priority. These are messages that are shown in normal operation */
constexpr int LOG_LEVEL_INFO = 1;
/** log message with verbose priority. These are still part of normal operation when higher logging verbosity is
 requested */
constexpr int LOG_LEVEL_VERB = 2;
/** debug log message priority. Only messages that are useful for a debugging a feature should fall into this
 * category */
constexpr int LOG_LEVEL_DEBUG = 3;
/** trace log message priority. Message that are normally even considered too verbose for the debug level priority
 * belong to this category. Messages that are otherwise often commented out in the code, belong here. */
constexpr int LOG_LEVEL_TRACE = 4;

/**
 * A class that simplifies the logging with different verbosity. It is
 * intended to be either used as a base class or preferably as a member.
 * The member can be either a normal member or static member depending
 * if setting the loglevel should affect all instances of the class or
 * only the current one.
 *
 * e.g.:
 *
 *      static inline logging::Logger<logging::LOG_LEVEL_INFO, logging::LOG_LEVEL_VERB> log_;
 *
 * and then when logging in the class use
 *
 * @tparam DEFAULT_LOG_LEVEL      the default loglevel for this class
 * @tparam MAX_LEVEL            the maximum loglevel that will be printed. Logging with higher
 *                              verbosity will be disabled by using if constexpr expressions.
 *                              Will be ignored and set to DEFAULT_LOG_LEVEL if DEFAULT_LOG_LEVEL
 *                              is higher than MAX_LEVEL.
 *
 *                              This allows to customise compile time maximum verbosity.
 */
template <int DEFAULT_LOG_LEVEL, int MAX_LEVEL = LOG_LEVEL_DEBUG>
class Logger
{
  public:
    static constexpr int max_log_level = std::max(MAX_LEVEL, DEFAULT_LOG_LEVEL);
    static constexpr int default_log_level = DEFAULT_LOG_LEVEL;


    //! return the current logging level for all logging
    int log_level()
    {
        return current_log_level;
    }

    //! set the log level for all loggigng
    void set_log_level(int level)
    {
        current_log_level = level;
    }


    /**
     * Prints a log message for tracing if the log level
     * is at least TRACE (=4)
     * @param msg   the message to print
     */
    template <typename T>
    void log_trace(T &&msg)
    {
        /* this ensures that the function is empty if MAX_LEVEL excludes this level */
        if constexpr (max_log_level >= LOG_LEVEL_TRACE)
        {
            if (current_log_level >= LOG_LEVEL_TRACE)
                OPENVPN_LOG(msg);
        }
    }

    /**
     * Prints a log message for debugging only info  if the log level
     * is at least DEBUG (=3)
     * @param msg   the message to print
     */
    template <typename T>
    void log_debug(T &&msg)
    {
        /* this ensures that the function is empty if MAX_LEVEL excludes this level */
        if constexpr (max_log_level >= LOG_LEVEL_DEBUG)
        {
            if (current_log_level >= LOG_LEVEL_DEBUG)
                OPENVPN_LOG(msg);
        }
    }


    /**
     * Prints a log message for general info  if the log level
     * is at least INFO (=1)
     * @param msg   the message to print
     */
    template <typename T>
    void log_info(T &&msg)
    {
        /* this ensures that the function is empty if MAX_LEVEL excludes this level */
        if constexpr (max_log_level >= LOG_LEVEL_INFO)
        {
            if (current_log_level >= LOG_LEVEL_INFO)
                OPENVPN_LOG(msg);
        }
    }

    /**
     * Prints a verbose log message like decompression ratio on individual packets if
     * the log level is at least VERB (=2)
     * @param msg   the message to log
     */

    template <typename T>
    void log_verbose(T &&msg)
    {
        /* this ensures that the function is empty if MAX_LEVEL excludes this level */
        if constexpr (max_log_level >= LOG_LEVEL_VERB)
        {
            if (current_log_level >= LOG_LEVEL_VERB)
                OPENVPN_LOG(msg);
        }
    }

    /**
     * Logs an error message that should almost always be logged
     * @param msg   the message to log
     */
    template <typename T>
    void log_error(T &&msg)
    {
        if (current_log_level >= LOG_LEVEL_ERROR)
            OPENVPN_LOG(msg);
    }

  protected:
    //! configured loglevel
    int current_log_level = DEFAULT_LOG_LEVEL;
};

/**
 * A mixin class that can be used as base class to expose the setting and getting of the log level publicly but not expose
 * the log methods themselves. Class parameters are the same as for \class Logger
 */
template <int DEFAULT_LOG_LEVEL, int MAX_LEVEL = LOG_LEVEL_TRACE>
class LoggingMixin
{
  public:
    //! return the current logging level for all logging
    static int log_level()
    {
        return log_.log_level;
    }

    //! set the log level for all loggigng
    static void set_log_level(int level)
    {
        log_.set_log_level(level);
    }

    static constexpr int max_log_level = logging::Logger<DEFAULT_LOG_LEVEL, MAX_LEVEL>::max_log_level;
    static constexpr int default_log_level = logging::Logger<DEFAULT_LOG_LEVEL, MAX_LEVEL>::default_log_level;

  protected:
    static inline logging::Logger<DEFAULT_LOG_LEVEL, MAX_LEVEL> log_;
};


/* Log helper macros that allow to not instantiate/execute the code that builds the log messsage if the message is
 * not logged or MAX_LEVEL is not compiled. This are not as nice as using the log_ members methods but are nicer than
 * other #defines that do not use if constexpr */

/**
 * Logging macro that logs with INFO verbosity using the logger named logger
 *
 * The macro tries very hard to avoid executing the
 * code that is inside args when logging is not happening
 */
#define LOGGER_LOG_INFO(logger, args)                                                      \
    do                                                                                     \
    {                                                                                      \
        if constexpr (decltype(logger)::max_log_level >= openvpn::logging::LOG_LEVEL_INFO) \
        {                                                                                  \
            if (logger.log_level() >= openvpn::logging::LOG_LEVEL_INFO)                    \
            {                                                                              \
                std::ostringstream _ovpn_log_ss;                                           \
                _ovpn_log_ss << args;                                                      \
                logger.log_info(_ovpn_log_ss.str());                                       \
            }                                                                              \
        }                                                                                  \
    } while (0)

/**
 * Logging macro that logs with VERB verbosity using the logger named logger
 *
 * The macro tries very hard to avoid executing the
 * code that is inside args when logging is not happening
 */
#define LOGGER_LOG_VERBOSE(logger, args)                                                   \
    do                                                                                     \
    {                                                                                      \
        if constexpr (decltype(logger)::max_log_level >= openvpn::logging::LOG_LEVEL_VERB) \
        {                                                                                  \
            if (logger.log_level() >= openvpn::logging::LOG_LEVEL_VERB)                    \
            {                                                                              \
                std::ostringstream _ovpn_log_ss;                                           \
                _ovpn_log_ss << args;                                                      \
                logger.log_verbose(_ovpn_log_ss.str());                                    \
            }                                                                              \
        }                                                                                  \
    } while (0)

/**
 * Logging macro that logs with DEBUG verbosity using the logger named logger
 *
 * The macro tries very hard to avoid executing the
 * code that is inside args when logging is not happening
 */
#define LOGGER_LOG_DEBUG(logger, args)                                                      \
    do                                                                                      \
    {                                                                                       \
        if constexpr (decltype(logger)::max_log_level >= openvpn::logging::LOG_LEVEL_DEBUG) \
        {                                                                                   \
            if (logger.log_level() >= openvpn::logging::LOG_LEVEL_DEBUG)                    \
            {                                                                               \
                std::ostringstream _ovpn_log_ss;                                            \
                _ovpn_log_ss << args;                                                       \
                logger.log_debug(_ovpn_log_ss.str());                                       \
            }                                                                               \
        }                                                                                   \
    } while (0)


/**
 * Logging macro that logs with TRACE verbosity using the logger named logger
 *
 * The macro tries very hard to avoid executing the
 * code that is inside args when logging is not happening
 */
#define LOGGER_LOG_TRACE(logger, args)                                                      \
    do                                                                                      \
    {                                                                                       \
        if constexpr (decltype(logger)::max_log_level >= openvpn::logging::LOG_LEVEL_TRACE) \
        {                                                                                   \
            if (logger.log_level() >= openvpn::logging::LOG_LEVEL_TRACE)                    \
            {                                                                               \
                std::ostringstream _ovpn_log_ss;                                            \
                _ovpn_log_ss << args;                                                       \
                logger.log_trace(_ovpn_log_ss.str());                                       \
            }                                                                               \
        }                                                                                   \
    } while (0)


#define LOG_INFO(args) LOGGER_LOG_INFO(log_, args)
#define LOG_VERBOSE(args) LOGGER_LOG_VERBOSE(log_, args)
#define LOG_DEBUG(args) LOGGER_LOG_DEBUG(log_, args)
#define LOG_TRACE(args) LOGGER_LOG_TRACE(log_, args)
} // namespace openvpn::logging
