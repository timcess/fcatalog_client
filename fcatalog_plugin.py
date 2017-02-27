import logging
import os
import idaapi
import idautils
import idc
import tempfile
import fcatalog_client.fcat_logger as fcat_logger

import time
import sys

from fcatalog_client.ida_client import FCatalogClient,clean_idb,MAX_SIM_GRADE
from fcatalog_client.db_endpoint import NetError
from fcatalog_client.fcatalog_forms import *
from fcatalog_client.fcatalog_forms_old import *
from fcatalog_client.thread_executor import ThreadExecutor



CONF_FILE_NAME = 'fcatalog_plugin.conf'

# Leave it empty if you want all output to be in IDA Output window
LOG_FILE_NAME = ''

# Or set it like this to have all output in plugin_service_dir()/LOG_FILE_NAME
#LOG_FILE_NAME = 'fcatalog_plugin.log'

LOG_LEVEL = logging.INFO

# Returns a path to the folder that contains a configuration file
# and ensures that this folder exists
def plugin_service_dir():
    # IDA is running on Windows
    if os.name == 'nt':
        base_dir = os.getenv('APPDATA')
        dir_name = 'fcatalog'

    # IDA is running on Linux
    if os.name == 'posix':
        base_dir = os.getenv('HOME')
        dir_name = '.fcatalog'

    plug_dir = os.path.join(base_dir, dir_name)
    if not os.path.isdir(plug_dir):
        os.mkdir(plug_dir)

    return plug_dir


# Set up logging
if LOG_FILE_NAME != '':
    log_file_path = os.path.join(plugin_service_dir(), LOG_FILE_NAME)
    logging.basicConfig(filename=log_file_path,level=LOG_LEVEL)
else:
    logging.basicConfig(stream=sys.stdout, level=LOG_LEVEL)


fcat_logger.logger = logging.getLogger()
logger = fcat_logger.logger


# Client configuration:
class ClientConfig(object):
    def __init__(self):
        self.db_name = None
        self.remote_host = None
        self.remote_port = None
        self.exclude_pattern = None

class FCatalogConfig(object):
    def __init__(self):
        self.exclude_pattern = None
        # Default value
        self.sim_grade = 9


##########################################################################

# Configuration stashing:

def save_sstring(s):
    """
    Save a short string inside the idb.
    """
    min_segment_addr = min(list(idautils.Segments()))
    # Keep the string as a regular comment on the first instruction:
    idc.MakeComm(min_segment_addr,s)


def load_sstring():
    """
    Load a short string from the idb.
    """
    min_segment_addr = min(list(idautils.Segments()))
    return idc.GetCommentEx(min_segment_addr,0)


def conf_file_write(string):
    plug_dir = plugin_service_dir()
    conf_file = os.path.join(plug_dir, CONF_FILE_NAME)
    with open(conf_file, 'w') as f:
        f.write(string)

def conf_file_read():
    plug_dir = plugin_service_dir()
    conf_file = os.path.join(plug_dir, CONF_FILE_NAME)
    if not os.path.exists(conf_file):
        return ""

    with open(conf_file, 'r') as f:
        data = f.read()

    return data

def save_config(client_config, fc_config):
    """
    Save configuration (client_config instance) to IDB.
    """
    config_str = "%%%"
    config_str += client_config.remote_host
    config_str += ":"
    config_str += str(client_config.remote_port)
    config_str += ":"
    config_str += client_config.db_name
    config_str += ":"
    if fc_config.exclude_pattern is not None:
        config_str += fc_config.exclude_pattern
    config_str += ":"
    config_str += str(fc_config.sim_grade)

    #save_sstring(config_str)
    conf_file_write(config_str)

def load_config():
    """
    Load configuration (client_config instance) to IDB.
    """
    #config_str = load_sstring()
    config_str = conf_file_read()

    fc_config = FCatalogConfig()

    if (config_str is None) or (not config_str.startswith('%%%')):
        # Return empty configuration:
        return [None, fc_config]

    # Skip the percents prefix:
    config_str = config_str[3:]

    try:
        remote_host,remote_port_str,db_name,exclude_pattern,sim_grade = config_str.split(':')
    except ValueError:
        # Abort if could not unpack 5 values
        return [None, fc_config]

    remote_port = int(remote_port_str)

    # Create a client config instance and fill it with the loaded
    # configuration:
    client_config = ClientConfig()
    client_config.remote_host = remote_host
    client_config.remote_port = remote_port
    client_config.db_name = db_name
    if len(exclude_pattern) == 0:
        client_config.exclude_pattern = None

    try:
        sgrade = int(sim_grade)
        fc_config.sim_grade = sgrade
    except Exception:
        pass

    if len(exclude_pattern) != 0:
        fc_config.exclude_pattern = exclude_pattern

    return [client_config, fc_config]



##########################################################################

def get_similarity_cut():
    """
    Get similarity cut value from the user.
    """
    # The default similarity cut grade is just above half:
    default_sim_cut = (MAX_SIM_GRADE // 2) + 1
    # We have to make sure that default_sim_cut is not more than
    # MAX_SIM_GRADE:
    default_sim_cut = min([default_sim_cut,MAX_SIM_GRADE])

    # Keep going until we get a valid sim_cut from the user, or the user picks
    # cancel.
    while True:
        sim_cut = idaapi.asklong(default_sim_cut,\
                "Please choose a similarity grade cut (1 - {}): ".\
                format(MAX_SIM_GRADE))
        if sim_cut is None:
            # If the user has aborted, we return None:
            return None
        if (1 <= sim_cut <= MAX_SIM_GRADE):
            break

    return sim_cut


class FCatalogPlugin(idaapi.plugin_t):
    flags = 0
    comment = ''
    help = 'The Functions Catalog client'
    wanted_name = 'fcatalog_client'
    wanted_hotkey = ''

    def init(self):
        """
        Initialize plugin:
        """
        cfgs = load_config()
        self._client_config = cfgs[0]
        self._fc_cfg = cfgs[1]

        self._fcc = None
        if self._client_config is not None:
            self._fcc = FCatalogClient(\
                    (self._client_config.remote_host,\
                    self._client_config.remote_port),\
                    self._client_config.db_name,\
                    self._client_config.exclude_pattern)

        # Make sure that self._client config is built, even if it doesn't have
        # any fields inside:
        if self._client_config is None:
            self._client_config = ClientConfig()

        # Set up menu:
        ui_path = "Edit/load"
        self.menu_contexts = []
        self.menu_contexts.append(idaapi.add_menu_item(ui_path,
                                "Reverse Catalog",
                                "",
                                0,
                                self._main_form,
                                (None,)))

        return idaapi.PLUGIN_KEEP

    def save_configuration(self):
        save_config(self._client_config, self._fc_cfg)
        
    def create_configuration(self, rhost, rport, db, patt, sim_grade):
        is_conf_good = True
        is_conf_new = False
        
        if self._client_config == None:
            self._client_config = ClientConfig()

        if self._fc_cfg == None:
            self._fc_cfg = FCatalogConfig()

        # Extract host:
        host = rhost
        if len(host) == 0:
            host = None
            is_conf_good = False
        if self._client_config.remote_host != host:
            is_conf_new = True
        self._client_config.remote_host = host

        # Extract port:
        try:
            port = int(rport)
        except ValueError:
            port = None
            is_conf_good = False
        if self._client_config.remote_port != port:
            is_conf_new = True
        self._client_config.remote_port = port

        # Extract db name:
        db_name = db
        if len(db_name) == 0:
            db_name = None
            is_conf_good = False

        # Check on path traversal
        if db_name.find('..') != -1:
            is_conf_good = False
        elif db_name.find('/') != -1:
            is_conf_good = False
        elif db_name.find('\\') != -1:
            is_conf_good = False
        else:
            if self._client_config.db_name != db_name:
                is_conf_new = True
            self._client_config.db_name = db_name

        # Extract exclude_pattern
        exclude_pattern = patt
        if len(exclude_pattern) == 0:
            exclude_pattern = None
        self._client_config.exclude_pattern = exclude_pattern
        self._fc_cfg.exclude_pattern = exclude_pattern

        # Extract default similartiy grade
        try:
            grade = int(sim_grade)
            if grade < 1 or grade > 16:
                is_conf_good = False
        except ValueError:
            grade = None
            is_conf_good = False
        self._fc_cfg.sim_grade = grade

        logger.debug("{} {} {} {}".format(self._client_config.remote_host, self._client_config.remote_port, self._client_config.db_name, self._client_config.exclude_pattern))

        if is_conf_good:
            save_config(self._client_config, self._fc_cfg)
            self._fcc = FCatalogClient(\
                    (self._client_config.remote_host,\
                    self._client_config.remote_port),\
                    self._client_config.db_name,\
                    self._client_config.exclude_pattern)
            logger.info('Configuration successful.')
        else:
            logger.info('Invalid configuration.')
            self._fcc = None

        return is_conf_new


    def run(self,arg):
        pass

    def term(self):
        """
        Terminate plugin
        """
        for context in self.menu_contexts:
            idaapi.del_menu_item(context)
        return None

    def _main_form(self, arg):
        self.main_frm = MainCatalog(fcp=self)
        self.main_frm.Show("Reverse Catalog")


    # Executes in the second thread
    # User shouldn't change any function while commiting isn't finished
    def commit_funcs(self, cb, cb_args):
        if self._fcc is None:
            logger.info('Please configure FCatalog')
            return

        check_res = self.main_frm.check_conn()
        if check_res == True:
            self._fcc.commit_funcs(cb, cb_args)


    def commit_structs(self):
        """
        This function handles the event of clicking on "commit funcs" from the
        menu.
        """
        if self._fcc is None:
            logger.info('Please configure FCatalog')
            return

        result = self.main_frm.check_conn()
        if result == True:
            self._fcc.commit_structs()

    def load_func_names(self):
        if self._fcc is None:
            logger.info('Please configure FCatalog')
            return

        result = self.main_frm.check_conn()
        if result == True:
            return self._fcc.load_func_names()
        else:
            return []

    def load_struct_names(self):
        if self._fcc is None:
            logger.info('Please configure FCatalog')
            return

        result = self.main_frm.check_conn()
        if result == True:
            return self._fcc.load_struct_names()
        else:
            return []
        

    def _load_all_structs(self, callb, cb_args):
        if self._fcc is None:
            logger.info('Please configure FCatalog')
            return
        #self._check_connection(self._fcc.load_all_structs)
        result = self.main_frm.check_conn()
        if result == True:
            self._fcc.load_all_structs(callb, cb_args)


    # Every time it found similar functions it executes callb
    # Executes in the second thread
    def find_similars(self, callb, cb_args):
        if self._fcc is None:
            logger.info('Please configure FCatalog')
            return

        similarity_cut = self._fc_cfg.sim_grade

        # If the user has clicked cancel, we abort:
        if similarity_cut is None:
            logger.info('Aborting find_similars.')
            return

        check_res = self.main_frm.check_conn()
        if check_res == True:
            self._fcc.find_similars(similarity_cut, callb, cb_args)


    # Executes in the main thread because it's fast enough
    def clean_fcat_names(self):
        """
        Clean the idb from fcatalog names or comments.
        """
        logger.debug("Start to clean FCatalog names")
        clean_idb()

def PLUGIN_ENTRY():
    return FCatalogPlugin()
