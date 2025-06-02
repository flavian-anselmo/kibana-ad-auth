# '''
# |------------      ------------------           ------------
# |  ldap_sync |--->| Active Directory |-------> | Maria DB   |
# |------------      ------------------           ------------


# ->  picks users info from ldap and populate new users  created from ldap
# ->  user status is set to pending_activation
# ->  check for password expiry for the users againist ldap 
import ldap
from configparser import ConfigParser
from typing import Optional, Tuple, Dict, Any, List
import logging

class ActiveDirectoryAuth:
    """
    A comprehensive Active Directory authentication class using LDAP.
    
    This class provides methods to authenticate users against an Active Directory
    server and retrieve user attributes.
    """
    
    def __init__(self, 
                 server: str = "10.19.2.7",
                 bind_user: str = "CN=Administrator,CN=Users,DC=eisp,DC=safaricombusiness,DC=co,DC=ke",
                 bind_password: str = "",
                 search_base: str = "DC=eisp,DC=safaricombusiness,DC=co,DC=ke",
                 user_ou: str = "OU=NPM_Users",
                 domain: str = "eisp.safaricombusiness.co.ke",
                 config_file: Optional[str] = None):
        """
        Initialize the ActiveDirectoryAuth class.
        
        Args:
            server: LDAP server IP or hostname
            bind_user: Service account DN for binding
            bind_password: Service account password
            search_base: Base DN for searches
            user_ou: Organizational Unit for users
            domain: Domain name
            config_file: Optional config file path to override defaults
        """
        self.server = server
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.search_base = search_base
        self.user_ou = user_ou
        self.domain = domain
        
        # Load from config file if provided
        if config_file:
            self._load_config(config_file)
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
    
    def _load_config(self, config_file: str) -> None:
        """Load configuration from file."""
        try:
            config = ConfigParser()
            config.read(config_file)
            
            self.server = config.get('ad', 'server', fallback=self.server)
            self.bind_user = config.get('ad', 'bind_user', fallback=self.bind_user)
            self.bind_password = config.get('ad', 'bind_password', fallback=self.bind_password)
            self.search_base = config.get('ad', 'search_base', fallback=self.search_base)
            self.user_ou = config.get('ad', 'user_ou', fallback=self.user_ou)
            self.domain = config.get('ad', 'domain', fallback=self.domain)
        except Exception as e:
            self.logger.warning(f"Could not load config file {config_file}: {e}")
    
    def get_connection(self) -> Optional[ldap.ldapobject.LDAPObject]:
        """
        Establish secure LDAP connection to AD using service account.
        
        Returns:
            LDAP connection object or None if connection fails
        """
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap.set_option(ldap.OPT_REFERRALS, 0)
            
            con = ldap.initialize(f"ldap://{self.server}")
            con.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            con.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            con.start_tls_s()
            con.simple_bind_s(self.bind_user, self.bind_password)
            
            return con
        except Exception as e:
            self.logger.error(f"AD Connection Error: {str(e)}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate a user against LDAP/AD using multiple DN formats.
        
        Args:
            username: Username to authenticate
            password: User's password
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Initialize LDAP connection settings
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap.set_option(ldap.OPT_REFERRALS, 0)
            
            # Try different username formats
            user_formats = [
                f"CN={username},{self.user_ou},{self.search_base}",  # Full DN in NPM_Users OU
                f"{username}@{self.domain}",  # UPN format
                f"CN={username},CN=Users,{self.search_base}",  # Users container
            ]
            
            # Try each format until one works
            last_error = None
            for user_dn in user_formats:
                try:
                    test_con = ldap.initialize(f"ldap://{self.server}")
                    test_con.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                    test_con.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
                    test_con.start_tls_s()
                    test_con.simple_bind_s(user_dn, password)
                    test_con.unbind_s()
                    
                    self.logger.info(f"Authentication successful for {username} with format: {user_dn}")
                    return True, f"Authentication successful with format: {user_dn}"
                except ldap.INVALID_CREDENTIALS:
                    last_error = "Invalid username or password"
                    continue
                except Exception as e:
                    last_error = str(e)
                    continue
            
            return False, last_error or "Authentication failed with all formats"
            
        except ldap.INVALID_CREDENTIALS:
            return False, "Invalid username or password"
        except ldap.SERVER_DOWN:
            return False, "LDAP server is not available"
        except ldap.LDAPError as e:
            return False, f"LDAP Error: {str(e)}"
        except Exception as e:
            return False, f"Authentication Error: {str(e)}"
    
    def authenticate_with_search(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate user by first searching for their DN, then binding.
        
        Args:
            username: Username to authenticate
            password: User's password
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        service_con = None
        user_con = None
        
        try:
            # First, connect with service account to search for user
            service_con = self.get_connection()
            if not service_con:
                return False, "Could not establish service connection"
            
            # Search for the user in multiple locations
            user_dn = self._find_user_dn(service_con, username)
            if not user_dn:
                return False, f"User '{username}' not found in AD"
            
            service_con.unbind_s()
            service_con = None
            
            # Now try to bind with the user's credentials
            user_con = self._create_user_connection(user_dn, password)
            if user_con:
                user_con.unbind_s()
                return True, "Authentication successful"
            else:
                return False, "Authentication failed"
                
        except ldap.INVALID_CREDENTIALS:
            return False, "Invalid username or password"
        except ldap.SERVER_DOWN:
            return False, "LDAP server is not available"
        except ldap.LDAPError as e:
            return False, f"LDAP Error: {str(e)}"
        except Exception as e:
            return False, f"Authentication Error: {str(e)}"
        finally:
            # Clean up connections
            self._cleanup_connections([service_con, user_con])
    
    def _find_user_dn(self, connection: ldap.ldapobject.LDAPObject, username: str) -> Optional[str]:
        """
        Search for user DN in multiple locations.
        
        Args:
            connection: Active LDAP connection
            username: Username to search for
            
        Returns:
            User DN if found, None otherwise
        """
        search_locations = [
            f"{self.user_ou},{self.search_base}",  # NPM_Users OU
            f"CN=Users,{self.search_base}",   # Default Users container
            self.search_base                   # Entire domain
        ]
        
        for search_base in search_locations:
            try:
                search_filter = f"(|(sAMAccountName={username})(cn={username})(userPrincipalName={username}@{self.domain}))"
                
                result = connection.search_s(
                    search_base, 
                    ldap.SCOPE_SUBTREE, 
                    search_filter, 
                    ['distinguishedName']
                )
                
                if result:
                    return result[0][0]  # Get the DN from search result
            except ldap.LDAPError:
                continue
        
        return None
    
    def _create_user_connection(self, user_dn: str, password: str) -> Optional[ldap.ldapobject.LDAPObject]:
        """
        Create a connection for user authentication.
        
        Args:
            user_dn: User's distinguished name
            password: User's password
            
        Returns:
            LDAP connection object or None if authentication fails
        """
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap.set_option(ldap.OPT_REFERRALS, 0)
            
            user_con = ldap.initialize(f"ldap://{self.server}")
            user_con.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            user_con.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            user_con.start_tls_s()
            user_con.simple_bind_s(user_dn, password)
            
            return user_con
        except Exception:
            return None
    
    def _cleanup_connections(self, connections: List[Optional[ldap.ldapobject.LDAPObject]]) -> None:
        """Clean up LDAP connections."""
        for conn in connections:
            try:
                if conn:
                    conn.unbind_s()
            except Exception:
                pass
    
    def get_user_attributes(self, username: str, password: str, 
                          attributes: Optional[List[str]] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Authenticate and return user attributes if successful.
        
        Args:
            username: Username to authenticate
            password: User's password
            attributes: List of attributes to retrieve (default: common attributes)
            
        Returns:
            Tuple of (success: bool, message: str, attributes: dict or None)
        """
        if attributes is None:
            attributes = ['displayName', 'mail', 'memberOf', 'department', 'telephoneNumber', 'title']
        
        try:
            # First authenticate
            is_auth, message = self.authenticate_with_search(username, password)
            if not is_auth:
                return False, message, None
            
            # If authentication successful, get user details
            con = self.get_connection()
            if not con:
                return True, "Authenticated but could not retrieve details", None
            
            try:
                search_filter = f"(|(sAMAccountName={username})(cn={username})(userPrincipalName={username}@{self.domain}))"
                
                result = con.search_s(
                    self.search_base,
                    ldap.SCOPE_SUBTREE,
                    search_filter,
                    attributes
                )
                
                if result:
                    user_attrs = result[0][1]  # Get attributes dictionary
                    # Convert byte values to strings for easier handling
                    processed_attrs = self._process_attributes(user_attrs)
                    return True, "Authentication successful", processed_attrs
                else:
                    return True, "Authenticated but user details not found", None
            finally:
                con.unbind_s()
                
        except Exception as e:
            return False, f"Error: {str(e)}", None
    
    def _process_attributes(self, attrs: Dict[str, List[bytes]]) -> Dict[str, Any]:
        """
        Process LDAP attributes to convert bytes to strings and handle lists.
        
        Args:
            attrs: Raw LDAP attributes dictionary
            
        Returns:
            Processed attributes dictionary
        """
        processed = {}
        
        for key, values in attrs.items():
            if isinstance(values, list):
                if len(values) == 1:
                    # Single value
                    processed[key] = values[0].decode('utf-8') if isinstance(values[0], bytes) else values[0]
                else:
                    # Multiple values (like memberOf)
                    processed[key] = [
                        val.decode('utf-8') if isinstance(val, bytes) else val 
                        for val in values
                    ]
            else:
                processed[key] = values.decode('utf-8') if isinstance(values, bytes) else values
        
        return processed
    
    def is_user_in_group(self, username: str, password: str, group_name: str) -> Tuple[bool, str, bool]:
        """
        Check if an authenticated user is a member of a specific group.
        
        Args:
            username: Username to check
            password: User's password
            group_name: Name of the group to check membership for
            
        Returns:
            Tuple of (auth_success: bool, message: str, is_member: bool)
        """
        is_auth, message, attrs = self.get_user_attributes(username, password, ['memberOf'])
        
        if not is_auth:
            return False, message, False
        
        if not attrs or 'memberOf' not in attrs:
            return True, "Authenticated but no group membership found", False
        
        member_of = attrs['memberOf']
        if isinstance(member_of, str):
            member_of = [member_of]
        
        # Check if group_name is in any of the group DNs
        is_member = any(group_name.lower() in group.lower() for group in member_of)
        
        return True, f"User membership check completed", is_member


# # Example usage
# if __name__ == "__main__":
#     # Initialize with default settings
#     ad_auth = ActiveDirectoryAuth()
    
#     # Or initialize with custom settings
#     # ad_auth = ActiveDirectoryAuth(
#     #     server="your-ad-server.com",
#     #     bind_user="CN=ServiceAccount,CN=Users,DC=company,DC=com",
#     #     bind_password="service_password",
#     #     search_base="DC=company,DC=com",
#     #     domain="company.com"
#     # )
    
#     # Or load from config file
#     # ad_auth = ActiveDirectoryAuth(config_file="/etc/elk_ad_sync.conf")
    
#     # Authenticate user
#     username = "testuser"
#     password = "testpassword"
    
#     # Simple authentication
#     success, message = ad_auth.authenticate_user(username, password)
#     print(f"Authentication: {success} - {message}")
    
#     # Authentication with search
#     success, message = ad_auth.authenticate_with_search(username, password)
#     print(f"Auth with search: {success} - {message}")
    
#     # Get user attributes
#     success, message, attrs = ad_auth.get_user_attributes(username, password)
#     if success and attrs:
#         print(f"User attributes: {attrs}")
    
#     # Check group membership
#     success, message, is_member = ad_auth.is_user_in_group(username, password, "Administrators")
#     print(f"Admin group member: {is_member}")