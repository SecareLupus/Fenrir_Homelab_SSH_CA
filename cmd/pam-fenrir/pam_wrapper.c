#include <security/pam_modules.h>
#include <security/pam_appl.h>

/* These are the Go functions exported via //export */
extern int go_pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, char **argv);
extern int go_pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, char **argv);

/* Entry point for PAM */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return go_pam_sm_authenticate(pamh, flags, argc, (char**)argv);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return go_pam_sm_setcred(pamh, flags, argc, (char**)argv);
}
