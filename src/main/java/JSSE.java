import com.stripe.Stripe;
import com.stripe.exception.StripeException;
import com.stripe.model.Charge;
import com.stripe.net.APIResource;

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
import java.util.HashMap;
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
    Stripe.apiKey = System.getenv("STRIPE_API_KEY");
    Map<String, Object> chargeMap = new HashMap<String, Object>();
    chargeMap.put("amount", 100);
    chargeMap.put("currency", "usd");
    Map<String, Object> cardMap = new HashMap<String, Object>();
    cardMap.put("number", "4242424242424242");
    cardMap.put("exp_month", 12);
    cardMap.put("exp_year", 2020);
    chargeMap.put("card", cardMap);
    try {
      Charge charge = Charge.create(chargeMap);
      System.out.println(charge);
    } catch (StripeException e) {
      e.printStackTrace();
    }
  }
}
