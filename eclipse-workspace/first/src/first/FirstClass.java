package first;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemObject;
import java.io.*;
import java.nio.file.Files;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
;

public class FirstClass {
	
	public static void main(String[] args)
	{
	    try 
	    {
	    	//List to store CA root certificates
	    	List<X509Certificate> ca_root = new ArrayList<>();
	    	//List to store the certificate chain
	    	List<X509Certificate> servercerts = new ArrayList<>();
	    	
	    	
	    	PKIXParameters validatorParams = null;
	    	CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
	        PemReader pemReader=null;
	        PemObject pemObject=null;
	        
	        //Load the CA root certificates
	        File cafile = new File("C:\\Users\\yamin\\Downloads\\cacert.pem");
	        pemReader = new PemReader(Files.newBufferedReader(cafile.toPath()));
	        while(true)
	        {
	        	pemObject = pemReader.readPemObject();
	        	if (pemObject == null) 
	                break;
	        	ca_root.add((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pemObject.getContent())));
	        }
	        

            //Load the certificate chain need to be checked  (End and intermediate, remove the root)
            File server_file = new File("C:\\Users\\yamin\\Downloads\\wikipedia-org-chain.pem");
	        pemReader = new PemReader(Files.newBufferedReader(server_file.toPath()));
	        while(true)
	        {
	        	pemObject = pemReader.readPemObject();
	        	if (pemObject == null) 
	                break;
	        	servercerts.add((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pemObject.getContent())));
	        }
	        
            // Custom trust store using the imported CAs
             Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
             for (X509Certificate cert : ca_root) 
             anchors.add(new TrustAnchor(cert, null));
               
              //Checking if the certificates in the chain are expired 
               for (int i = 0; i < servercerts.size(); i++) 
                   servercerts.get(i).checkValidity(); 
               
			    // Path validation 
                //Check certificate revocation using OSCP 
			    //Generate path
				//Validate the path
             
				// check if the CA used hasn't expired 
                validatorParams = new PKIXParameters(anchors);
                validatorParams.setRevocationEnabled(true);

                Security.setProperty("ocsp.enable", "true");
                System.setProperty("com.sun.net.ssl.checkRevocation", "true");
                System.setProperty("com.sun.security.enableCRLDP", "true");
                
                CertPath certPath = certFactory.generateCertPath(servercerts);
                CertPathValidatorResult result = validator.validate(certPath,validatorParams);
                ((PKIXCertPathValidatorResult) result).getTrustAnchor().getTrustedCert().checkValidity();
                
                 System.out.println("Valid");
	    }
	    catch(Exception e)
	    {
	    	System.out.println(e);
	    }
	}

	
}
