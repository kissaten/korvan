import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.net.URLStreamHandler;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Map;

public class JSSE {
  public static void main(String... args) throws Exception {
    sunJsseAndTlsv12();
    stripe();
  }

  public static void sunJsseAndTlsv12() throws KeyManagementException {
    // Create the context.  Specify the SunJSSE provider to avoid
    // picking up third-party providers.  Try the TLS 1.2 provider
    // first, then fall back to TLS 1.0.
    SSLContext ctx;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "SunJSSE");
    } catch (NoSuchAlgorithmException e) {
      try {
        ctx = SSLContext.getInstance("TLSv1", "SunJSSE");
      } catch (NoSuchAlgorithmException e1) {
        // The TLS 1.0 provider should always be available.
        throw new AssertionError(e1);
      } catch (NoSuchProviderException e1) {
        throw new AssertionError(e1);
      }
    } catch (NoSuchProviderException e) {
      // The SunJSSE provider should always be available.
      throw new AssertionError(e);
    }
    ctx.init(null, null, null);
    System.out.println("Created SSLContext: " + "TLSv1.2, SunJSSE");
  }

  public static void stripe() throws Exception {
    String url = "https://api.stripe.com";
    URL stripeURL = new URL(null, url);

    java.net.HttpURLConnection hconn = (java.net.HttpURLConnection) stripeURL.openConnection();

    javax.net.ssl.HttpsURLConnection conn = (javax.net.ssl.HttpsURLConnection) hconn;
    conn.connect();
    Certificate[] certs = conn.getServerCertificates();

    MessageDigest md = MessageDigest.getInstance("SHA-1");
    byte[] der = certs[0].getEncoded();
    md.update(der);
    byte[] digest = md.digest();
    byte[] revokedCertDigest = {(byte) 0x05, (byte) 0xc0, (byte) 0xb3, (byte) 0x64, (byte) 0x36, (byte) 0x94, (byte) 0x47, (byte) 0x0a, (byte) 0x88, (byte) 0x8c, (byte) 0x6e, (byte) 0x7f, (byte) 0xeb, (byte) 0x5c, (byte) 0x9e, (byte) 0x24, (byte) 0xe8, (byte) 0x23, (byte) 0xdc, (byte) 0x53};
    if (Arrays.equals(digest, revokedCertDigest)) {
      throw new RuntimeException();
    }
    System.out.println("Created HTTPSConnection: " + conn.getResponseCode());
  }
}
