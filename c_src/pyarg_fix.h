// To be included after Python.h

// Fix builds created with python3.13 and greater
// https://discuss.python.org/t/c-stable-api-py-ssize-t-clean-error/80159/3
//   also https://github.com/python/cpython/issues/71686#issuecomment-3014285820
PyAPI_FUNC(int) _PyArg_ParseTuple_SizeT(PyObject *, const char *, ...);
#undef PyArg_ParseTuple
#define PyArg_ParseTuple _PyArg_ParseTuple_SizeT
