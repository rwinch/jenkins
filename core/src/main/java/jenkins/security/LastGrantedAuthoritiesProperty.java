package jenkins.security;

import hudson.Extension;
import hudson.model.Descriptor.FormException;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Remembers the set of {@link GrantedAuthority}s that was obtained the last time the user has logged in.
 *
 * This allows us to implement {@link User#impersonate()} with proper set of groups.
 *
 * @author Kohsuke Kawaguchi
 * @since 1.556
 * @see ImpersonatingUserDetailsService
 */
public class LastGrantedAuthoritiesProperty extends UserProperty {
    private volatile String[] roles;
    private long timestamp;

    /**
     * Stick to the same object since there's no UI for this.
     */
    @Override
    public UserProperty reconfigure(StaplerRequest req, JSONObject form) throws FormException {
    	req.bindJSON(this, form);
    	return this;
    }

    public Collection<GrantedAuthority> getAuthorities() {
        String[] roles = this.roles;    // capture to a variable for immutability

        List<GrantedAuthority> r = new ArrayList<GrantedAuthority>();
        r.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        if (roles != null) {
            for (int i = 1; i < roles.length; i++) {
                r.add(new SimpleGrantedAuthority(roles[i - 1]));
            }
        }
        return r;
    }

    /**
     * Persist the information with the new {@link UserDetails}.
     */
    public void update(@Nonnull Authentication auth) throws IOException {
        List<String> roles = new ArrayList<String>();
        for (GrantedAuthority ga : auth.getAuthorities()) {
            roles.add(ga.getAuthority());
        }
        String[] a = roles.toArray(new String[roles.size()]);
        if (!Arrays.equals(this.roles,a)) {
            this.roles = a;
            this.timestamp = System.currentTimeMillis();
            user.save();
        }
    }

    /**
     * Removes the recorded information
     */
    public void invalidate() throws IOException {
        if (roles!=null) {
            roles = null;
            timestamp = System.currentTimeMillis();
            user.save();
        }
    }

    /**
     * Listen to the login success/failure event to persist {@link GrantedAuthority}s properly.
     */
    @Extension
    public static class SecurityListenerImpl extends SecurityListener {
        @Override
        protected void authenticated(@Nonnull UserDetails details) {
        }

        @Override
        protected void failedToAuthenticate(@Nonnull String username) {
        }

        @Override
        protected void loggedIn(@Nonnull String username) {
            try {
                User u = User.get(username);
                LastGrantedAuthoritiesProperty o = u.getProperty(LastGrantedAuthoritiesProperty.class);
                if (o==null)
                    u.addProperty(o=new LastGrantedAuthoritiesProperty());
                Authentication a = Jenkins.getAuthentication();
                if (a!=null && a.getName().equals(username))
                    o.update(a);    // just for defensive sanity checking
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to record granted authorities",e);
            }
        }

        @Override
        protected void failedToLogIn(@Nonnull String username) {
            // while this initially seemed like a good idea to avoid allowing wrong impersonation for too long,
            // doing this means a malicious user can break the impersonation capability
            // just by failing to login. See ApiTokenFilter that does the following, which seems better:
            /*
                try {
                    Jenkins.getInstance().getSecurityRealm().loadUserByUsername(username);
                } catch (UserMayOrMayNotExistException x) {
                    // OK, give them the benefit of the doubt.
                } catch (UsernameNotFoundException x) {
                    // Not/no longer a user; deny the API token. (But do not leak the information that this happened.)
                    chain.doFilter(request, response);
                    return;
                } catch (DataAccessException x) {
                    throw new ServletException(x);
                }
             */

//            try {
//                User u = User.get(username,false,Collections.emptyMap());
//                LastGrantedAuthoritiesProperty o = u.getProperty(LastGrantedAuthoritiesProperty.class);
//                if (o!=null)
//                    o.invalidate();
//            } catch (IOException e) {
//                LOGGER.log(Level.WARNING, "Failed to record granted authorities",e);
//            }
        }

        @Override
        protected void loggedOut(@Nonnull String username) {
        }
    }

    @Extension
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @Override
        public boolean isEnabled() {
            return false;
        }
        
        public UserProperty newInstance(User user) {
            return null;
        }
    }

    private static final Logger LOGGER = Logger.getLogger(LastGrantedAuthoritiesProperty.class.getName());
}
