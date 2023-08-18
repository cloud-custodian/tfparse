# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from cffi import FFI

ffi = FFI()

ffi.set_source(
    "tfparse._tfparse",
    None,
    include_dirs=[],
    extra_compile_args=["-march=native"],
    libraries=[],
)

ffi.cdef(
    """
        typedef struct {
            char *json;
            char *err;
        } parseResponse;

        parseResponse Parse(char* a, int stop_on_error, int debug, int allow_downloads, int num_vars_files, char** vars_files);
        void free(void *ptr);
        """  # noqa
)
ffi.compile()
