#!/usr/bin/python3
from gi.repository import GLib

import dbus
import dbus.service
import dbus.mainloop.glib
import sys
import os
import threading
import time
import collections
import datetime
import weakref

from abc import ABCMeta, abstractmethod
from enum import Enum

from config import ctx

CONNMAN_STORAGE_DIR =           '/tmp/connman'
CONNMAN_CONFIG_DIR =            '/tmp'

CONNMAN_SERVICE =               'net.connman'
CONNMAN_ERROR_INTERFACE =       'net.connman.Error'
CONNMAN_AGENT_INTERFACE =       'net.connman.Agent'
CONNMAN_COUNTER_INTERFACE =     'net.connman.Counter'
CONNMAN_MANAGER_INTERFACE =     'net.connman.Manager'
CONNMAN_CLOCK_INTERFACE =       'net.connman.Clock'
CONNMAN_TASK_INTERFACE =        'net.connman.Task'
CONNMAN_SERVICE_INTERFACE =     'net.connman.Service'
CONNMAN_TECHNOLOGY_INTERFACE =  'net.connman.Techonolgy'
CONNMAN_SESSION_INTERFACE =     'net.connman.Session'
CONNMAN_NOTIFICATION_INTERFACE ='net.connman.Notification'
CONNMAN_PEER_INTERFACE =        'net.connman.Peer'
CONNMAN_VPN_INTERFACE =         'net.connman.vpn'

CONNMAN_MANAGER_PATH =          '/'

class AlreadyConnectedEx(dbus.DBusException): pass
class AlreadyDisabledEx(dbus.DBusException): pass
class AlreadyEnabledEx(dbus.DBusException): pass
class AlreadyExistsEx(dbus.DBusException): pass
class FailedEx(dbus.DBusException): pass
class InProgressEx(dbus.DBusException): pass
class InvalidArgumentsEx(dbus.DBusException): pass
class InvalidPropertyEx(dbus.DBusException): pass
class InvalidServiceEx(dbus.DBusException): pass
class NoCarrierEx(dbus.DBusException): pass
class NotConnectedEx(dbus.DBusException): pass
class NotFoundEx(dbus.DBusException): pass
class NotImplementedEx(dbus.DBusException): pass
class NotRegisteredEx(dbus.DBusException): pass
class NotUniqueEx(dbus.DBusException): pass
class OperationAbortedEx(dbus.DBusException): pass
class OperationCanceledEx(dbus.DBusException): pass
class OperationTimeoutEx(dbus.DBusException): pass
class PassphraseRequiredEx(dbus.DBusException): pass
class PermissionDeniedEx(dbus.DBusException): pass


_dbus_ex_to_py = {
    'AlreadyConnected' :    AlreadyConnectedEx,
    'AlreadyDisabled' :     AlreadyDisabledEx,
    'AlreadyEnabled' :      AlreadyEnabledEx,
    'AlreadyExists' :       AlreadyExistsEx,
    'Failed' :              FailedEx,
    'InProgress' :          InProgressEx,
    'InvalidArguments' :    InvalidArgumentsEx,
    'InvalidProperty' :     InvalidPropertyEx,
    'InvalidService' :      InvalidServiceEx,
    'NoCarrier' :           NoCarrierEx,
    'NotConnected':         NotConnectedEx,
    'NotFound' :            NotFoundEx,
    'NotImplemented' :      NotImplementedEx,
    'NotRegistered' :       NotRegisteredEx,
    'NotUnique' :           NotUniqueEx,
    'OperationAborted' :    OperationAbortedEx,
    'OperationCanceled' :   OperationCanceledEx,
    'OperationTimeout' :    OperationTimeoutEx,
    'PassphraseRequired' :  PassphraseRequiredEx,
    'Permissiondenied' :    PermissionDeniedEx,
}


def _convert_dbus_ex(dbus_ex):
    ex_name = dbus_ex.get_dbus_name()
    ex_short_name = ex_name[ex_name.rfind(".") + 1:]
    if ex_short_name in _dbus_ex_to_py:
        return _dbus_ex_to_py[ex_short_name](dbus_ex)
    else:
        return UnknownDBusEx(ex_name + ': ' + dbus_ex.get_dbus_message())


class AsyncOpAbstract(object):
    __metaclass__ = ABCMeta

    _is_completed = False
    _exception = None

    def _success(self):
        self._is_completed = True

    def _failure(self, ex):
        self._is_completed = True
        self._exception = _convert_dbus_ex(ex)

    def _wait_for_async_op(self):
        context = ctx.mainloop.get_context()
        while not self._is_completed:
            context.iteration(may_block=True)

        self._is_completed = False
        if self._exception is not None:
            tmp = self._exception
            self._exception = None
            raise tmp


class ConnManDBusAbstract(AsyncOpAbstract):
    __metaclass__ = ABCMeta

    def __init__(self, object_path=None, properties=None, service=CONNMAN_SERVICE, namespace=ctx):
        self._bus = namespace.get_bus()
        self._namespace = namespace

        self._object_path = object_path
        self.proxy = self._bus.get_object(service, self._object_path)
        self._iface = dbus.Interface(self.proxy, self._iface_name)

        if properties is None:
            self._properties = self._iface.GetProperties()
        else:
            self._properties = properties

        self._iface.connect_to_signal("PropertyChanged",
                                      self._property_changed_handler,
                                      service,
                                      path_keyword="path")

    def _property_changed_handler(self, interface, changed, invalidated, path):
        if interface == self._iface_name and path == self._object_path:
            for name, value in changed.items():
                self._properties[name] = value

    @abstractmethod
    def __str__(self):
        pass


class ServiceState(Enum):
    '''Conection state of a service'''
    idle =          'idle'
    failure =       'failure'
    association =   'assocation'
    configuration = 'configuration'
    ready =         'ready'
    online =        'online'
    disconnect =    'disconnect'

    def __str__(self):
        return self.value

    @classmethod
    def from_str(cls, string):
        return getattr(cls, string, None)


class ServiceType(Enum):
    '''The type of a service'''
    system =        'system'
    ethernet =      'ethernet'
    wifi =          'wifi'
    bluetooth =     'bluetooth'
    cellular =      'cellular'
    gps =           'gps'
    vpn =           'vpn'
    gadget =        'gadget'
    p2p =           'p2p'

    def __str__(self):
        return self.value

    @classmethod
    def from_str(cls, string):
        return getattr(cls, string, None)


class SecurityType(Enum):
    '''Service's security type'''
    none =            'none'
    wep =             'wep'
    psk =             'psk'
    ieee8021x =       'ieee8021x'
    wps =             'wps'
    wps_advertizing = 'wps_advertizing'

    def __str__(self):
        return str(self.value)

    @classmethod
    def from_string(cls, string):
        type = None
        for attr in dir(cls):
            if (str(getattr(cls, attr)) == string):
                type = getattr(cls, attr)
                break
        return type


class ErrorType(Enum):
    '''Service's error type'''
    out_of_range =    'out-of-range'
    pin_missing =     'pin-missing'
    dhcp_failed =     'dhcp-failed'
    connect_failed =  'connect-failed'
    login_failed =    'login-failed'
    auth_failed =     'auth-failed'
    invalid_key =     'invalid-key'
    blocked =         'blocked'

    def __str__(self):
        return str(self.value)

    @classmethod
    def from_string(cls, string):
        type = None
        for attr in dir(cls):
            if (str(getattr(cls, attr)) == string):
                type = getattr(cls, attr)
                break
        return type


class ManagerState(Enum):
    '''Conection state'''
    idle =          'idle'
    offline =       'offline'
    ready =         'ready'
    online =        'online'

    def __str__(self):
        return self.value

    @classmethod
    def from_str(cls, string):
        return getattr(cls, string, None)


class Service(ConnManDBusAbstract):
    '''
        Class represents a network device object: net.connman.Service
        with its properties and methods
    '''
    _iface_name = CONNMAN_SERVICE_INTERFACE

    def __init__(self, *args, **kwargs):
        ConnManDBusAbstract.__init__(self, *args, **kwargs)

    @property
    def path(self):
        '''
            Service's D-Bus path.

            @rtype: string
        '''
        return self._object_path

    @property
    def state(self):
        '''
            Reflects the general network connection state.

            @rtype: object (State)
        '''
        return ServiceState.from_str(self._properties['State'])

    @property
    def error(self):
        '''
            Service's error details.

            @rtype: object (Error)
        '''
        return ErrorType.from_str(self._properties['Error'])

    @property
    def name(self):
        '''
            Service's interface name.

            @rtype: string
        '''
        return self._properties['Name']

    @property
    def type(self):
        '''
            Service's type.

            @rtype: object (Type)
        '''
        return ServiceType.from_str(self._properties['Type'])

    @property
    def security(self):
        '''
            Service's security type.

            @rtype: object (Security)
        '''
        return SecurityType.from_str(self._properties['Security'])

    @property
    def strength(self):
        '''
            Signal strength of the service.

            @rtype: number
        '''
        return int(self._properties['Strength'])

    @property
    def favorite(self):
        '''
            True if cable is plugged in or the user
            selected and successfully conntect to this service.

            @rtype: boolean
        '''
        return bool(self._properties['Favorite'])

    @property
    def immutable(self):
        '''
            True if service is configured externally.

            @rtype: boolean
        '''
        return bool(self._properties['Immutable'])

    @property
    def autoconnect(self):
        '''
            True if service will auto connect.

            @rtype: boolean
        '''
        return bool(self._properties['AutoConnect'])

    @property
    def roaming(self):
        '''
            True if service is roaming.

            @rtype: boolean
        '''
        return bool(self._properties['Roaming'])

    # XXX add missing complex properites

    def connect(self):
        '''Connect this service.

           Possible exception: InvalidArgumentsEx
        '''
        self._iface.Connect(dbus_interface=CONNMAN_SERVICE_INTERFACE,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()

    def disconnect(self):
        '''Disconnect this service

           Possible exception: InvalidArgumentsEx
        '''
        self._iface.Disconnect(dbus_interface=CONNMAN_SERVICE_INTERFACE,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()


    def remove(self):
        '''Remove this service

           Possible exception: InvalidArgumentsEx
        '''
        self._iface.Remove(dbus_interface=CONNMAM_SERVICE_INTERFACE,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()

    def move_before(self, other):
        '''Move this service before other service

           Possible exception: InvalidArgumentsEx
        '''
        self._iface.MoveBevore(dbus_interface=CONNMAM_SERVICE_INTERFACE,
                               service=other,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()

    def move_after(self, other):
        '''Move this service after other service

           Possible exception: InvalidArgumentsEx
        '''
        self._iface.MoveAfter(dbus_interface=CONNMAM_SERVICE_INTERFACE,
                               service=other,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()

    def reset_counters(self, other):
        '''Reset the counter statistics.

           Possible exception: None
        '''
        self._iface.ResetCounters(dbus_interface=CONNMAM_SERVICE_INTERFACE,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()

    def __str__(self, prefix = ''):
        return prefix + 'Service: ' + self.path + '\n'\
               + prefix + '\tName:\t\t' + self.name + '\n'\
               + prefix + '\tState:\t\t' + str(self.state) + '\n'


class Manager(ConnManDBusAbstract):
    '''Class represents a manager object: net.connman.Manager'''
    _iface_name = CONNMAN_MANAGER_INTERFACE

    @property
    def path(self):
        '''
            Manager's D-Bus path.

            @rtype: string
        '''
        return self._object_path

    @property
    def state(self):
        '''
            Reflects the general connection state.

            @rtype: object (State)
        '''
        return ManagerState.from_str(self._properties['State'])

    @property
    def offline_mode(self):
        '''
            True if system is offlined.

            @rtype: boolean
        '''
        return bool(self._properties['OfflineMode'])


    def get_services(self):
        services = []
        for bus_obj, props in self._iface.GetServices():
            services.append(Service(bus_obj, properties=props))

        if len(services) > 0:
            return services

        return None

    def __str__(self, prefix = ''):
        return prefix + 'Manager:\n' \
                + prefix + '\tState:\t' + str(self.state) + '\n' \
                + prefix + '\tOfflineMode:\t' + str(self.offline_mode)


class ConnMan(AsyncOpAbstract):
    '''
        Start an ConnMan instance.
    '''
    _manager = None
    _connman_proc = None
    _default_instance = None
    _services = None

    def __init__(self, start_connman_daemon = False, connman_config_dir = '/tmp',
                            connman_storage_dir = '/tmp/connman', namespace=ctx):
        self.namespace = namespace
        self._bus = namespace.get_bus()

        if start_connman_daemon:
            if self.namespace.is_process_running('connmand'):
                raise Exception("ConnMan requested to start but is already running")

            self._connman_proc = self.namespace.start_connman(connman_config_dir,
                                                              connman_storage_dir)

        tries = 0
        while not self._bus.name_has_owner(CONNMAN_SERVICE):
            if not ctx.args.gdb:
                if tries > 200:
                    if start_connman_daemon:
                        self.namespace.stop_process(self._connman_proc)
                        self._connman_proc = None
                    raise TimeoutError('ConnMan has failed to start')
                tries += 1
            time.sleep(0.1)

        self._manager = Manager(CONNMAN_MANAGER_PATH, properties=None,
                                namespace=self.namespace)
        # Weak to make sure the test's reference to @self is the only counted
        # reference so that __del__ gets called when it's released. This is only
        # done for the root namespace in order to allow testutil to function
        # correctly in non-namespace tests.
        if self.namespace.name == "root":
            ConnMan._default_instance = weakref.ref(self)

    def __del__(self):
        self._manager = None

        if self._connman_proc is not None:
            self.namespace.stop_process(self._connman_proc)
            self._connman_proc = None

        self.namespace = None

    def get_manager(self):
        if self._manager:
            return self._manager

        self._wait_timed_out = False
        def wait_timeout_cb():
            self._wait_timed_out = True
            return False

        try:
            timeout = GLib.timeout_add_seconds(max_wait, wait_timeout_cb)
            context = ctx.mainloop.get_context()
            while not self._manager:
                context.iteration(may_block=True)
                if self._wait_timed_out:
                    raise TimeoutError('IWD has no associated devices')
        finally:
            if not self._wait_timed_out:
                GLib.source_remove(timeout)

        return self._manager

    @staticmethod
    def _wait_for_object_condition(obj, condition_str, max_wait = 50):
        class TimeoutData:
            _wait_timed_out = False

        data = TimeoutData()

        def wait_timeout_cb(data):
            data._wait_timed_out = True
            return False

        try:
            timeout = GLib.timeout_add_seconds(max_wait, wait_timeout_cb, data)
            context = ctx.mainloop.get_context()
            while not eval(condition_str):
                context.iteration(may_block=True)
                if data._wait_timed_out and ctx.args.gdb == None:
                    raise TimeoutError('[' + condition_str + ']'\
                                       ' condition was not met in '\
                                       + str(max_wait) + ' sec')
        finally:
            if not data._wait_timed_out:
                GLib.source_remove(timeout)

    def wait_for_object_condition(self, *args, **kwargs):
        self._wait_for_object_condition(*args, **kwargs)

    def wait_for_object_change(self, obj, from_str, to_str, max_wait = 50):
        '''
            Expects condition 'from_str' to evaluate true while waiting for 'to_str'. If
            at any point during the wait 'from_str' evaluates false, an exception is
            raised.

            This allows an object to be checked for a state transition without any
            intermediate state changes.
        '''
        self._wait_timed_out = False

        def wait_timeout_cb():
            self._wait_timed_out = True
            return False

        # Does initial condition pass?
        if not eval(from_str):
            raise Exception("initial condition [%s] not met" % from_str)

        try:
            timeout = GLib.timeout_add_seconds(max_wait, wait_timeout_cb)
            context = ctx.mainloop.get_context()
            while True:
                context.iteration(may_block=True)

                # If neither the initial or expected condition evaluate the
                # object must be in another unexpected state.
                if not eval(from_str) and not eval(to_str):
                    raise Exception('unexpected condition between [%s] and [%s]' % from_str, to_str)

                # Initial condition does not evaluate but expected does, pass
                if not eval(from_str) and eval(to_str):
                    break

                if self._wait_timed_out and ctx.args.gdb == None:
                    raise TimeoutError('[' + to_str + ']'\
                                       ' condition was not met in '\
                                       + str(max_wait) + ' sec')
        finally:
            if not self._wait_timed_out:
                GLib.source_remove(timeout)

    def wait(self, time):
        self._wait_timed_out = False
        def wait_timeout_cb():
            self._wait_timed_out = True
            return False

        try:
            timeout = GLib.timeout_add(int(time * 1000), wait_timeout_cb)
            context = ctx.mainloop.get_context()
            while not self._wait_timed_out:
                context.iteration(may_block=True)
        finally:
            if not self._wait_timed_out:
                GLib.source_remove(timeout)

    @staticmethod
    def clear_storage(storage_dir=CONNMAN_STORAGE_DIR):
        os.system('rm -rf ' + storage_dir + '/*')

    @staticmethod
    def create_in_storage(file_name, file_content):
        fo = open(CONNMAN_STORAGE_DIR + '/' + file_name, 'w')

        fo.write(file_content)
        fo.close()

    @staticmethod
    def copy_to_storage(source, storage_dir=CONNMAN_STORAGE_DIR):
        import shutil

        assert not os.path.isabs(source)

        shutil.copy(source, storage_dir)

    @staticmethod
    def remove_from_storage(file_name):
        os.system('rm -rf ' + CONNMAN_STORAGE_DIR + '/\'' + file_name + '\'')

    @staticmethod
    def get_instance():
        return ConnMan._default_instance()
