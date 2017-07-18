package fun.personalacademics.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Optional;

import javax.xml.bind.DatatypeConverter;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import javafx.collections.ObservableList;
import javafx.scene.control.TreeItem;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;

import com.zeva.temp.jaxb.datamodel.AddressType;
import com.zeva.temp.jaxb.datamodel.DigitalIdentityListType;
import com.zeva.temp.jaxb.datamodel.DigitalIdentityType;
import com.zeva.temp.jaxb.datamodel.ElectronicAddressType;
import com.zeva.temp.jaxb.datamodel.ExtensionsListType;
import com.zeva.temp.jaxb.datamodel.InternationalNamesType;
import com.zeva.temp.jaxb.datamodel.MultiLangNormStringType;
import com.zeva.temp.jaxb.datamodel.NonEmptyMultiLangURIListType;
import com.zeva.temp.jaxb.datamodel.OtherTSLPointersType;
import com.zeva.temp.jaxb.datamodel.PostalAddressListType;
import com.zeva.temp.jaxb.datamodel.PostalAddressType;
import com.zeva.temp.jaxb.datamodel.TSPInformationType;
import com.zeva.temp.jaxb.datamodel.TSPServiceInformationType;
import com.zeva.temp.jaxb.datamodel.TSPServiceType;
import com.zeva.temp.jaxb.datamodel.TSPType;
import com.zeva.temp.jaxb.datamodel.TrustServiceProviderListType;
import com.zeva.temp.jaxb.datamodel.TrustStatusListType;
import com.zeva.tlGen.dataModel.CertificateBean;
import com.zeva.tlGen.dataModel.ProviderAttribute;
import com.zeva.tlGen.dataModel.TLPointer;

public class TrustListUtilFactory extends CertificateUtilities{
		
	public static void deleteSelectedItems(List<CertificateBean> all,
			List<CertificateBean> selected) {
		for (int i = selected.size() - 1; i >= 0; i--) {
			all.remove(selected.get(i));
		}
	}
	
	
	public PrivateKey getPrivateKey(String password, String alias){
		PrivateKey privKey = null;
		try {
			String storeName = "KeyStore.jks";
		    
		    KeyStore inStore = KeyStore.getInstance("PKCS12");
		    inStore.load(new FileInputStream(storeName), password.toCharArray());
		    privKey = (PrivateKey)inStore.getKey(alias, password.toCharArray());
		  } catch (Exception e) {
		    e.printStackTrace();
		    throw new AssertionError(e.getMessage());
		  }
		return privKey;
	}
	
	public X509Certificate getCertificate(String alias, String password){
		String storeName = "KeyStore.jks";
		X509Certificate cert = null;
		
		try {
			KeyStore outStore = KeyStore.getInstance("PKCS12");
			InputStream stream = new FileInputStream(storeName);
			outStore.load(stream, password.toCharArray());
			cert = (X509Certificate)outStore.getCertificate(alias);
			stream.close();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return cert;
	}
	
	public void inputPrivateKeyAndCert(String password, String keyAlias,
			String certAlias, X509Certificate cert, PrivateKey key){
		try {
			String storeName = "KeyStore.jks";

		    // Note: if you just want to store this certificate then write the
		    // contents of selfCert.getEncoded() to file

		    Certificate[] outChain = { cert };
		    InputStream stream = new FileInputStream(storeName);
		    KeyStore outStore = KeyStore.getInstance("PKCS12");
		    outStore.load(stream, password.toCharArray());
		    outStore.setKeyEntry(keyAlias, key, password.toCharArray(),
		        outChain);
		    outStore.setCertificateEntry(certAlias, cert);
		    stream.close();
		    OutputStream outputStream = new FileOutputStream(storeName);
		    outStore.store(outputStream, password.toCharArray());
		    outputStream.flush();
		    outputStream.close();
	 	} catch (Exception e) {
		    e.printStackTrace();
		    throw new AssertionError(e.getMessage());
		}
	}
	
	public void inputCertificate(X509Certificate cert, String password, String alias){
		try{
			String storeName = "KeyStore.jks";
			KeyStore outStore = KeyStore.getInstance("PKCS12");
			InputStream stream = new FileInputStream(storeName);
		    outStore.load(stream, password.toCharArray());
		    outStore.setCertificateEntry(alias, cert);
		    stream.close();
		    
		    OutputStream outputStream = new FileOutputStream(storeName);
		    outStore.store(outputStream, password.toCharArray());
		    outputStream.flush();
		    outputStream.close();
		} catch (Exception e) {
		    e.printStackTrace();
		    throw new AssertionError(e.getMessage());
		}
	}

	public List<ExtensionFilter> getSupportedExtFilters() {
		List<ExtensionFilter> filters = new ArrayList<>();
		filters.add(new ExtensionFilter("All Supported Certificates", "*.pem",
				"*.cer"));
		filters.add(new ExtensionFilter("Privacy Enhanced Mail", "*.pem"));
		filters.add(new ExtensionFilter("Security Certificate", "*.cer"));
		return filters;
	}

	public TrustStatusListType buildTrustList(List<ProviderAttribute> beans, TrustStatusListType tl) throws FileNotFoundException {
		System.out.println(tl.getSchemeInformation().getExperimentalElement());
		TSPType tsp = createEmptyTSPType();
		
		for(ProviderAttribute prov : beans){
			DigitalIdentityType cert = prov.<DigitalIdentityType>getEncapsulatedBean();
			
			TSPServiceType service = new TSPServiceType();
			TSPServiceInformationType info = new TSPServiceInformationType();
			
			InternationalNamesType serviceName = new InternationalNamesType();
			MultiLangNormStringType name = new MultiLangNormStringType();
			name.setLang("en");
			name.setValue(cert.getStringName());
			serviceName.getName().add(name);
			info.setServiceName(serviceName);
			
			info.setServiceTypeIdentifier("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
			
			try {
				GregorianCalendar c = new GregorianCalendar();
				c.setTime(cert.getParentCert().getNotBefore());
				info.setStatusStartingTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(c));
			} catch (DatatypeConfigurationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			info.setServiceStatus(cert.isRevoked() ? "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
					: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");
			
			DigitalIdentityListType idList = new DigitalIdentityListType();
			idList.getDigitalId().add(cert);
			info.setServiceDigitalIdentity(idList);
			
			service.setServiceInformation(info);
			
			tsp.getServices().add(service);
		}
		
		TrustServiceProviderListType tspList = new TrustServiceProviderListType();
		tl.setTrustServiceProviderList(tspList);
		tl.getTrustServiceProviderList().getTrustServiceProvider().add(tsp);
		System.out.println(tl.getTrustServiceProviderList().getTrustServiceProvider().get(0).getTSPServices());
		return tl;
	}
	
	public TreeItem<ProviderAttribute> buildProvider(TSPType provider){
		TreeItem<ProviderAttribute> tsp = new TreeItem<ProviderAttribute>(provider);
		for(TSPServiceType service : provider.getServices()){
			TreeItem<ProviderAttribute> serviceNode = buildService(service);
			tsp.getChildren().add(serviceNode);		
		}
		
		return tsp;
	}
	
	public TreeItem<ProviderAttribute> buildService(TSPServiceType service){
		TreeItem<ProviderAttribute> serviceNode = new TreeItem<ProviderAttribute>(service.initialize());
		
		for(DigitalIdentityType cert : service.getAllDigitalIDs()){	
			ProviderAttribute attr = cert.initialize();
			if(cert.getParentCert() != null){
				serviceNode.getChildren().add(new TreeItem<ProviderAttribute>(attr));
			}
		}
		
		return serviceNode;
	}
	
	public TreeItem<ProviderAttribute> buildCertificate(DigitalIdentityType cert){
		cert.initialize();
		return cert.getParentCert() != null ? new TreeItem<ProviderAttribute>(cert) : null;		
	}

	public void exportNodesToPem(List<TreeItem<ProviderAttribute>> nodes,
			File location) throws CertificateEncodingException, IOException {
		List<X509Certificate> certs = new ArrayList<>();
		for (TreeItem<ProviderAttribute> node : nodes)
			certs.add(node.getValue().<DigitalIdentityType>getEncapsulatedBean().getParentCert());

		exportCertsToPem(certs, location);

	}

	public static void exportCertsToPem(List<X509Certificate> certs,
			File location) throws CertificateEncodingException, IOException {

		List<String> encodedCerts = new ArrayList<>();
		for (X509Certificate cert : certs) {
			byte[] binary = cert.getEncoded();
			String base64 = DatatypeConverter.printBase64Binary(binary);
			String formatedBase64 = insertPeriodically(
					base64.replaceAll("\r", ""), "\r", 65);
			String begin = "-----BEGIN CERTIFICATE-----\n";
			String end = "\n-----END CERTIFICATE-----";
			encodedCerts.add(begin + formatedBase64 + end);
		}

		PrintWriter writer = new PrintWriter(new FileWriter(location));
		for (String formattedCert : encodedCerts) {
			writer.println(formattedCert);
		}
		writer.close();
	}
	
	public List<ProviderAttribute> extractCertificates(TrustStatusListType tl){
		List<ProviderAttribute> certs = new ArrayList<ProviderAttribute>();
		for(TSPType tsp : tl.getTrustServiceProviderList().getTrustServiceProvider()){
			for(TSPServiceType service : tsp.getServices()){
				certs.addAll(service.getCerts());
			}
		}
		
		return certs;
	}
	
	public TSPType createEmptyTSPType(){
		TSPType provider = new TSPType();
		TSPInformationType info = new TSPInformationType();
		
		AddressType addr = new AddressType();
		PostalAddressListType postAddrList = new PostalAddressListType();
		ElectronicAddressType elecAdd = new ElectronicAddressType();
		addr.setPostalAddresses(postAddrList);
		addr.setElectronicAddress(elecAdd);
		info.setTSPAddress(addr);
		
		info.setTSPInformationExtensions(new ExtensionsListType());
		info.setTSPInformationURI(new NonEmptyMultiLangURIListType());
		info.setTSPName(new InternationalNamesType());
		info.setTSPTradeName(new InternationalNamesType());
		
		provider.setTSPInformation(info);
		return provider;
		
	}
	
	
	public List<ExtensionFilter> getSupportedSigningFilters(){
		List<ExtensionFilter> filters = new ArrayList<FileChooser.ExtensionFilter>();
		filters.add(new ExtensionFilter("PFX File", "*.pfx"));
		filters.add(new ExtensionFilter("PKSC12 File", "*.p12"));
		return filters;
	}
	
	public TrustStatusListType buildTrustListofLists(List<TreeItem<TLPointer>> pointers, TrustStatusListType tl){
		OtherTSLPointersType pointerList = new OtherTSLPointersType();
		for(TreeItem<TLPointer> pointer : pointers){
			pointerList.getOtherTSLPointer().add(pointer.getValue().getEncapsulatedBean());
		}
		
		tl.getSchemeInformation().setPointersToOtherTSL(pointerList);
		
		return tl;
	}

}
