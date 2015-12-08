/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

import jenkins.security.ImpersonatingUserDetailsService;

/**
 * {@link TokenBasedRememberMeServices} with modification so as not to rely
 * on the user password being available.
 *
 * <p>
 * This allows remember-me to work with security realms where the password
 * is never available in clear text.
 *
 * @author Kohsuke Kawaguchi
 */
public class TokenBasedRememberMeServices2 extends TokenBasedRememberMeServices {

    public TokenBasedRememberMeServices2(String key, UserDetailsService userDetailsService) {
        super(key, new NoPasswordUserDetailsService(new ImpersonatingUserDetailsService(userDetailsService)));
    }

    static class NoPasswordUserDetailsService implements UserDetailsService {
        private final UserDetailsService delegate;

        public NoPasswordUserDetailsService(UserDetailsService delegate) {
            this.delegate = delegate;
        }

        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            UserDetails ud = delegate.loadUserByUsername(username);

            return new User(ud.getUsername(), "N/A", ud.isEnabled(), ud.isAccountNonExpired(), ud.isCredentialsNonExpired(), ud.isAccountNonLocked(), ud.getAuthorities());
        }
    }
}
