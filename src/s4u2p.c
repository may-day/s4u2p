/**
 * Copyright (c) 2006-2009 Apple Inc. All rights reserved.
 * Copyright (c) 2012 Norman Krämer. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

/**
 * This is a derivative work of the kerberos 1.1.1 package http://trac.calendarserver.org/
 */

#include <Python.h>

#include "kerberosgss.h"

PyObject *KrbException_class;
PyObject *GssException_class;

static PyObject* authGSSImpersonationInit(PyObject* self, PyObject* args, PyObject* keywds)
{
    const char *service, *as_user;
    gss_impers_state *state;
    PyObject *pystate;
    static char *kwlist[] = {"as_user", "service", "gssflags", NULL};
    long int gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;
    int result = 0;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|s|l", kwlist, &as_user, &service, &gss_flags))
        return NULL;

    state = (gss_impers_state *) malloc(sizeof(gss_impers_state));
    pystate = PyCObject_FromVoidPtr(state, NULL);

    result = authenticate_gss_impers_init(as_user, service, gss_flags, state);
    if (result == AUTH_GSS_ERROR)
        return NULL;

    return Py_BuildValue("(iO)", result, pystate);
}

static PyObject *authGSSImpersonationClean(PyObject *self, PyObject *args)
{
    gss_impers_state *state;
    PyObject *pystate;
    int result = 0;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_impers_state *)PyCObject_AsVoidPtr(pystate);
    if (state != NULL)
    {
        result = authenticate_gss_impers_clean(state);

        free(state);
        PyCObject_SetVoidPtr(pystate, NULL);
    }

    return Py_BuildValue("i", result);
}

static PyObject *authGSSImpersonationCleanCtx(PyObject *self, PyObject *args)
{
    gss_impers_state *state;
    PyObject *pystate;
    int result = 0;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_impers_state *)PyCObject_AsVoidPtr(pystate);
    if (state != NULL)
    {
        result = authenticate_gss_impers_cleanctx(state);

    }

    return Py_BuildValue("i", result);
}

static PyObject *authGSSImpersonationStep(PyObject *self, PyObject *args)
{
    gss_impers_state *state;
    PyObject *pystate;
    char *challenge;
    int result = 0;

    if (!PyArg_ParseTuple(args, "Os", &pystate, &challenge))
        return NULL;

    if (!PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_impers_state *)PyCObject_AsVoidPtr(pystate);
    if (state == NULL)
        return NULL;

    result = authenticate_gss_impers_step(state, challenge);
    if (result == AUTH_GSS_ERROR)
        return NULL;

    return Py_BuildValue("i", result);
}

static PyObject *authGSSImpersonationResponse(PyObject *self, PyObject *args)
{
    gss_impers_state *state;
    PyObject *pystate;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_impers_state *)PyCObject_AsVoidPtr(pystate);
    if (state == NULL)
        return NULL;

    return Py_BuildValue("s", state->response);
}

static PyObject *authGSSImpersonationUserName(PyObject *self, PyObject *args)
{
    gss_impers_state *state;
    PyObject *pystate;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_impers_state *)PyCObject_AsVoidPtr(pystate);
    if (state == NULL)
        return NULL;

    return Py_BuildValue("s", state->username);
}

static PyObject *authUse_keytab(PyObject *self, PyObject *args)
{
    char *keytab;
    int result = 0;

    if (!PyArg_ParseTuple(args, "s", &keytab))
        return NULL;

    result = authenticate_gss_use_keytab(keytab);
    if (result == AUTH_GSS_ERROR)
        return NULL;

    return Py_BuildValue("i", result);
}

static PyMethodDef S4U2PKerberosMethods[] = {
    {"authGSSKeytab",  authUse_keytab, METH_VARARGS,
	     "Set keytab to use in GSSAPI operations."},
    {"authGSSImpersonationInit",  (PyCFunction)authGSSImpersonationInit, METH_VARARGS | METH_KEYWORDS,
     "Initialize impersonation GSSAPI operations."},
    {"authGSSImpersonationClean",  authGSSImpersonationClean, METH_VARARGS,
     "Terminate impersonation GSSAPI operations."},
     {"authGSSImpersonationCleanCtx",  authGSSImpersonationCleanCtx, METH_VARARGS,
      "Prepare existing context for reuse in impersonation GSSAPI operations. An additional authGSSImpersonationInit can be avoided if you want to contact the same service impersoanted as the same user again."},
    {"authGSSImpersonationStep",  authGSSImpersonationStep, METH_VARARGS,
     "Do a Impersonation GSSAPI step."},
    {"authGSSImpersonationResponse",  authGSSImpersonationResponse, METH_VARARGS,
     "Get the response from the last Impersonation GSSAPI step."},
    {"authGSSImpersonationUserName",  authGSSImpersonationUserName, METH_VARARGS,
     "Get the user name from the last Impersonation GSSAPI step."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC inits4u2p(void)
{
    PyObject *m,*d;

    m = Py_InitModule("s4u2p", S4U2PKerberosMethods);

    d = PyModule_GetDict(m);

    /* create the base exception class */
    if (!(KrbException_class = PyErr_NewException("kerberos.KrbError", NULL, NULL)))
        goto error;
    PyDict_SetItemString(d, "KrbError", KrbException_class);
    Py_INCREF(KrbException_class);

    /* ...and the derived exceptions */
    if (!(GssException_class = PyErr_NewException("kerberos.GSSError", KrbException_class, NULL)))
        goto error;
    Py_INCREF(GssException_class);
    PyDict_SetItemString(d, "GSSError", GssException_class);

    PyDict_SetItemString(d, "AUTH_GSS_COMPLETE", PyInt_FromLong(AUTH_GSS_COMPLETE));
    PyDict_SetItemString(d, "AUTH_GSS_CONTINUE", PyInt_FromLong(AUTH_GSS_CONTINUE));

    PyDict_SetItemString(d, "GSS_C_DELEG_FLAG", PyInt_FromLong(GSS_C_DELEG_FLAG));
    PyDict_SetItemString(d, "GSS_C_MUTUAL_FLAG", PyInt_FromLong(GSS_C_MUTUAL_FLAG));
    PyDict_SetItemString(d, "GSS_C_REPLAY_FLAG", PyInt_FromLong(GSS_C_REPLAY_FLAG));
    PyDict_SetItemString(d, "GSS_C_SEQUENCE_FLAG", PyInt_FromLong(GSS_C_SEQUENCE_FLAG));
    PyDict_SetItemString(d, "GSS_C_CONF_FLAG", PyInt_FromLong(GSS_C_CONF_FLAG));
    PyDict_SetItemString(d, "GSS_C_INTEG_FLAG", PyInt_FromLong(GSS_C_INTEG_FLAG));
    PyDict_SetItemString(d, "GSS_C_ANON_FLAG", PyInt_FromLong(GSS_C_ANON_FLAG));
    PyDict_SetItemString(d, "GSS_C_PROT_READY_FLAG", PyInt_FromLong(GSS_C_PROT_READY_FLAG));
    PyDict_SetItemString(d, "GSS_C_TRANS_FLAG", PyInt_FromLong(GSS_C_TRANS_FLAG));

error:
    if (PyErr_Occurred())
        PyErr_SetString(PyExc_ImportError, "kerberos: init failed");
}
