#ifndef COMMON_CONFIG_PATH_H
#define COMMON_CONFIG_PATH_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * Resolve a config file path using ANTIDDOS_CONFIG_DIR environment variable.
 *
 * If ANTIDDOS_CONFIG_DIR is set, prepends it to the relative path.
 * Otherwise returns the original relative path (backwards compatible).
 *
 * @param relative_path  Relative config path (e.g. "layer1/config/layer1_config.json")
 * @param buf            Buffer to store resolved path
 * @param bufsz          Size of buffer
 * @return Pointer to resolved path (either buf or relative_path)
 */
static inline const char *resolve_config_path(const char *relative_path,
                                               char *buf, size_t bufsz) {
    const char *config_dir = getenv("ANTIDDOS_CONFIG_DIR");
    if (config_dir && config_dir[0] != '\0') {
        snprintf(buf, bufsz, "%s/%s", config_dir, relative_path);
        if (access(buf, R_OK) == 0) {
            return buf;
        }
        /* Fall through to relative path if resolved path not readable */
    }
    return relative_path;
}

#endif /* COMMON_CONFIG_PATH_H */
