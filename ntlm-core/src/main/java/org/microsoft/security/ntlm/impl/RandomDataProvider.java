/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

/**
 * Random data provider. Is used for test purposes.
 *
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public interface RandomDataProvider {
    byte[] nonce(int length);

    byte[] msTimestamp();
}
