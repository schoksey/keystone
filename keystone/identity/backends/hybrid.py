__author__ = 'schoksey'

from keystone import exception
from keystone import identity
from keystone.identity.backends import sql
from keystone.identity.backends import ldap
from keystone.openstack.common import log as logging
from oslo.config import cfg
from keystone import config as ks_cfg
from keystone.common.ldap import core
import re

CONF = ks_cfg.CONF
# create and register custom opts
ks_cfg.CONF.register_opt(cfg.StrOpt('user_suffix'), group='ldap')
ks_cfg.CONF.register_opt(cfg.StrOpt('generic_tree_dn'), group='ldap')
ks_cfg.CONF.register_opt(cfg.ListOpt('builtin_users'), group='ldap')

DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id
LDAP_BIND_USER = CONF.ldap.user
LDAP_BIND_PASSWORD = CONF.ldap.password
LDAP_CN_SUFFIX= CONF.ldap.user_suffix
LDAP_USER_OBJECT_CLASS = CONF.ldap.user_objectclass
LDAP_USER_ID_ATTRIBUTE = CONF.ldap.user_id_attribute
LDAP_USER_TREE_DN = CONF.ldap.user_tree_dn
LDAP_GENERIC_TREE_DN = CONF.ldap.generic_tree_dn
LDAP_BUILTIN_USERS = CONF.ldap.builtin_users

LOG = logging.getLogger(__name__)


class Identity(sql.Identity):

    def __init__(self):
        super(Identity, self).__init__()
        self.ldap_identity_api = ldap.Identity()

    def authenticate(self, user_id=None, password=None):
        """Authenticate based Cisco AD
        (schoksey): general flow
        0. Check if it is an openstack service user and default to SQL driver authentication
        1. If not, in built-in user list, lookup user in LDAP first to verify if user exists in LDAP
        2. If it does, then authenticate against ldap
        3. If it does not, then default to the keystone SQLDriver authentication
        NOTE: Password is NEVER persisted in the keystone db for LDAP non-local users
        """
        LOG.debug("Authenticating against HYBRID Driver")

        user_ref = self.get_user(user_id)
        #try:
        #    user_ref = self.get_user(user_id)
        #except exception.UserNotFound:
        #    pass


        if self._is_built_in_user(user_ref.get('name')):
            return super(Identity, self).authenticate(user_ref.get('id'), password)

        try:
            ldap_user = self._lookup_username_in_ad(user_ref.get('name'))
            
            if ldap_user is not None \
                and user_ref.get('name') == self._lookup_username_in_ad(user_ref.get('name')):
                conn = self.ldap_identity_api.user.get_connection(
                    self._resolve_cn_suffix(user_ref.get('name')), password)
                if not conn:
                    raise AssertionError('Invalid user / password')
                else:
                    if not (user_ref.get('enabled')):
                        user = {}
                        user['enabled'] = True
                        self.update_user(user_id, user)
                    return (identity.filter_user(self.get_user(user_id)))
            else:
                return super(Identity, self).authenticate(user_ref.get('id'), password)
        except Exception as error:
            LOG.error("EXCEPTION : %s" % error.message)
            raise AssertionError(error.message)


    def _resolve_cn_suffix(self, user_id):
        return ''.join([LDAP_USER_ID_ATTRIBUTE,'=',user_id,',',LDAP_CN_SUFFIX]) if LDAP_CN_SUFFIX else user_id


    def _lookup_username_in_ad(self, username):
        conn = self.ldap_identity_api.user.get_connection(LDAP_BIND_USER, LDAP_BIND_PASSWORD)
        baseDN = self._resolve_baseDN(username)
        
        query = "(&({}={})(objectClass={}))".format(LDAP_USER_ID_ATTRIBUTE,username,LDAP_USER_OBJECT_CLASS)
        attr_list = [LDAP_USER_ID_ATTRIBUTE]
        o = conn.search_s(baseDN, core.LDAP_SCOPES.get('one'), query, attr_list)
        if o is not None and len(o) > 0:
            return (o[0][1])[LDAP_USER_ID_ATTRIBUTE][0]


    def _resolve_baseDN(self, username):
        return LDAP_GENERIC_TREE_DN if re.search('\.gen$', username) else LDAP_USER_TREE_DN

    def _is_built_in_user(self, username):
        if username in LDAP_BUILTIN_USERS: 
            return True
        else:
            return False
