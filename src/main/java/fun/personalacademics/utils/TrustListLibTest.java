package fun.personalacademics.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import com.zeva.temp.jaxb.datamodel.DigitalIdentityType;
import com.zeva.temp.jaxb.datamodel.ObjectFactory;
import com.zeva.temp.jaxb.datamodel.TrustStatusListType;
import com.zeva.tlGen.dataModel.ProviderAttribute;

public class TrustListLibTest {

	public static void main(String[] args) throws Exception {
//		KeyPairGenerator keyPairGenerator = KeyPairGenerator
//		        .getInstance("RSA");
//	    keyPairGenerator.initialize(2048);
//	    KeyPair keyPair = keyPairGenerator.generateKeyPair();
//	    PublicKey publicKey = keyPair.getPublic();
//	    PrivateKey privateKey = keyPair.getPrivate();
	    //TrustListUtilFactory fac = new TrustListUtilFactory();
//	    X509Certificate selfCert = CertificateUtilities.createCertificate(
//	    		"CN=Trans Sped SAFE CA III","CN=SAFE Bridge CA 02", publicKey, privateKey);
//	    fac.inputPrivateKeyAndCert("password", "newKey", "newCert", selfCert, privateKey);
//		
//		System.out.println(fac.getPrivateKey("password", "newKey").getAlgorithm());
//		
//		System.out.println(fac.getCertificate("myName", "password"));
		
		
//		PrivateKey key = fac.getPrivateKey("password", "newKey");
//		System.out.println(key.getAlgorithm());
//		X509Certificate cert = fac.getCertificate("newCert", "password");
//		XMLTrustListUnmarshaller um = new JAXBTrustListUnmarshallerV5(new File("C:/Users/Karottop/Desktop/EU_71(Sn158).xml")); // EU_71(Sn158).xml
//		XMLTrustListMarshaller ma = new JAXBTrustListMarshallerV5(um.getTrustList());
//		ma.marshalTrustList();
//		ISignatureSigner signer = new XADES4JSignatureSigner(ma.getMarshalledDocument(), key, cert);
//		IPrinter printer = new TrustListXMLPrinter(signer, ma.getMarshalledDocument());
////		signer.signDocument();
//		printer.signAndPrint(new File("TestXML.xml"));
		
//		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
//		factory.setNamespaceAware(true);
//		DocumentBuilder builder = factory.newDocumentBuilder();
//		Document doc = builder.parse(new FileInputStream("TestXML.xml"), "UTF-8");
//		Document doc = builder.parse(new FileInputStream("C:/Users/Karottop/Desktop/EU_71(Sn158).xml"), "UTF-8");
		
//		doc.normalize();
//		TLVerifier verify = new TLVerifier(doc);
//		System.out.println(verify.signatureIsValid());
//		System.out.println(verify.isXmlDigitalSignatureValid(doc, publicKey));
//		String unicode = String.format("\\" + "u", 2081);
//		System.out.println("3\u2000x".replace("\u2000x", unicode));
//		
//		ByteArrayInputStream xmlContentBytes = new ByteArrayInputStream (new File("C:/Users/Karottop/Desktop/TrustedList-versiunea-xml.xml"));
//		JAXBContext context = JAXBContext.newInstance(TrustStatusListType.class);
//		Unmarshaller um = context.createUnmarshaller();
//		um.setSchema(null);
//		JAXBElement<TrustStatusListType> fact = (JAXBElement<TrustStatusListType>) um.unmarshal(new File("C:/Users/Karottop/Desktop/TrustedList-versiunea-xml.xml"));
//		ProviderAttribute cert = (fact.getValue()).getTrustServiceProviderList().getTrustServiceProvider().get(0).getTSPServices().getTSPService().get(0).getServiceInformation().getServiceDigitalIdentity().getDigitalId().get(0);
//		TrustStatusListType parent = fact.getValue();
//		CertificateFactory factory = CertificateFactory.getInstance("X.509");
//		X509Certificate certificate = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(cert));
//		System.out.println(fact.getValue().getSignature().getId());
//		
//		Marshaller ma = context.createMarshaller();
//		// output pretty printed
//		ma.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
//		ma.marshal(parent, new File("defaultSettings.xml"));
		
		
	}
	
	
	


}
