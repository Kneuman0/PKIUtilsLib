package fun.personalacademics.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.security.cert.X509Certificate;

import fun.personalacademics.model.CertificateBean;
import fun.personalacademics.popup.PasswordPopup;
import javafx.scene.control.ButtonType;

@SuppressWarnings("restriction")
public class CertificateEncapsulater {
	
	public static enum CERT_TYPES {CER, DER, PEM, CRT, P7B, P7C, PFX, P12, DEFAULT_KEYSTORE};
	List<X509Certificate> certs;
	
	/**
	 * Uses the file extension to determine the file type. Reads in the entire file and 
	 * stores it as X509Certificates
	 * @param certFile
	 * @throws Exception 
	 */
	public CertificateEncapsulater(File certFile) throws Exception {
		certs = new ArrayList<>();
		if(certFile.getAbsolutePath().toLowerCase().endsWith("cer")){
			loadCERFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith("pem")){
			loadPEMFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith("p7b") ||
				certFile.getAbsolutePath().toLowerCase().endsWith("p7c")){
			loadP7BFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith("pfx")){
			loadPFXFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith("p12")){
			loadP7BFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith("crt")){
			loadPEMFile(certFile);
		}else{
			throw new Exception(certFile.getAbsolutePath() + "is not a supported file type");
		}
		
		
	}
	
	/**
	 * Uses the file extension to determine the file type. Reads in the entire file and 
	 * stores it as X509Certificates
	 * @param certFile
	 * @throws Exception 
	 */
	public CertificateEncapsulater(URL url) throws Exception {
		certs = new ArrayList<>();
		if(url.getPath().toLowerCase().endsWith("cer")){
			loadCERURL(url);
		}else if(url.getPath().toLowerCase().endsWith("pem")){
			loadPEMURL(url);
		}else if(url.getPath().toLowerCase().endsWith("p7b") ||
				url.getPath().toLowerCase().endsWith("p7c")){
			loadP7BURL(url);
		}else if(url.getPath().toLowerCase().endsWith("pfx")){
			loadPFXURL(url);
		}else if(url.getPath().toLowerCase().endsWith("p12")){
			loadP7BURL(url);
		}else if(url.getPath().toLowerCase().endsWith("crt")){
			loadPEMURL(url);
		}else{
			throw new Exception(url.getPath() + "is not a supported file type");
		}
		
		
	}
	
	
	/**
	 * Reads in the certificate file and encapsulates the certificates using the method type specified.
	 * @param base64 base 64 string containing certificate information. Each certificate must be
	 * 		bounded at the beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by -----END CERTIFICATE-----.
	 * @param type type of certificate file being passed in
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 * @throws CMSException
	 */
	public CertificateEncapsulater(String base64, CERT_TYPES type) throws Exception{
		certs = new ArrayList<>();
		if(type == CERT_TYPES.CRT){
			loadPEMFile(base64);
		}else if(type == CERT_TYPES.PEM){
			loadPEMFile(base64);
		}else {
			throw new Exception("The only supported base 64 certificates extensions are CRT and PEM");
		}
	}
	
	/**
	 * Accepts a certificate file containing one or more certificates. Must specify the encoding type of the file. This
	 * constructor is useful if the certificate file is encoded differently then what the extension indicates
	 * @param certFile file containing one or more certificates
	 * @param ext type of certificate encoding
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 * @throws CMSException
	 */
	public CertificateEncapsulater(File certFile, CERT_TYPES ext)throws Exception{
		certs = new ArrayList<>();
		if(ext == CERT_TYPES.CER){
			loadCERFile(certFile);
		}else if(ext == CERT_TYPES.PEM){
			loadPEMFile(certFile);
		}else if(ext == CERT_TYPES.PFX){
			loadPFXFile(certFile);
		}else if(ext == CERT_TYPES.CRT){
			loadPEMFile(certFile);
		}else if(ext == CERT_TYPES.P7B){
			loadP7BFile(certFile);
		}else if(ext == CERT_TYPES.DER){
			loadCERFile(certFile);
		}else if(ext == CERT_TYPES.DEFAULT_KEYSTORE){
			addCertsFromDefaultJavaKeyStore(certFile, null);
		}else {
			// Must be type P7C
			loadP7BFile(certFile);
		}
	}
	
	/**
	 * Accepts a certificate file containing one or more certificates. Must specify the encoding type of the file. This
	 * constructor is useful if the certificate file is encoded differently then what the extension indicates
	 * @param certFile file containing one or more certificates
	 * @param ext type of certificate encoding
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 * @throws CMSException
	 */
	public CertificateEncapsulater(File certFile, CERT_TYPES ext, String password)throws Exception{
		certs = new ArrayList<>();
		if(ext == CERT_TYPES.CER){
			loadCERFile(certFile);
		}else if(ext == CERT_TYPES.PEM){
			loadPEMFile(certFile);
		}else if(ext == CERT_TYPES.PFX){
			loadPFXFile(certFile);
		}else if(ext == CERT_TYPES.CRT){
			loadPEMFile(certFile);
		}else if(ext == CERT_TYPES.P7B){
			loadP7BFile(certFile);
		}else if(ext == CERT_TYPES.DER){
			loadCERFile(certFile);
		}else if(ext == CERT_TYPES.DEFAULT_KEYSTORE){
			addCertsFromDefaultJavaKeyStore(certFile, password);
		}else {
			// Must be type P7C
			loadP7BFile(certFile);
		}
	}
	
	/**
	 * Accepts a certificate file containing one or more certificates. Must specify the encoding type of the file. This
	 * constructor is useful if the certificate file is encoded differently then what the extension indicates
	 * @param certFile file containing one or more certificates
	 * @param ext type of certificate encoding
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 * @throws CMSException
	 */
	public CertificateEncapsulater(URL url, CERT_TYPES ext)throws Exception{
		certs = new ArrayList<>();
		if(ext == CERT_TYPES.CER){
			loadCERURL(url);
		}else if(ext == CERT_TYPES.PEM){
			loadPEMURL(url);
		}else if(ext == CERT_TYPES.PFX){
			loadPFXURL(url);
		}else if(ext == CERT_TYPES.CRT){
			loadPEMURL(url);
		}else if(ext == CERT_TYPES.P7B){
			loadP7BURL(url);
		}else if(ext == CERT_TYPES.DER){
			loadCERURL(url);
		}else if(ext == CERT_TYPES.DEFAULT_KEYSTORE){
			addCertsFromDefaultJavaKeyStore(url, null);
		}else {
			// Must be type P7C
			loadP7BURL(url);
		}
	}
	
	public CertificateEncapsulater(URL url, CERT_TYPES ext, String password)throws Exception{
		certs = new ArrayList<>();
		if(ext == CERT_TYPES.CER){
			loadCERURL(url);
		}else if(ext == CERT_TYPES.PEM){
			loadPEMURL(url);
		}else if(ext == CERT_TYPES.PFX){
			loadPFXURL(url);
		}else if(ext == CERT_TYPES.CRT){
			loadPEMURL(url);
		}else if(ext == CERT_TYPES.P7B){
			loadP7BURL(url);
		}else if(ext == CERT_TYPES.DER){
			loadCERURL(url);
		}else if(ext == CERT_TYPES.DEFAULT_KEYSTORE){
			addCertsFromDefaultJavaKeyStore(url, password);
		}else {
			// Must be type P7C
			loadP7BURL(url);
		}
	}
	
	/**
	 * Method for loading cer encoded certificate file
	 * @param certFile file containing certificate
	 * @throws CertificateException
	 * @throws IOException
	 */
	private void loadCERFile(File certFile) throws CertificateException, IOException{
		addCertsFromFile("X.509", certFile);
	}
	
	/**
	 * Method for loading cer encoded certificate file
	 * @param certFile file containing certificate
	 * @throws CertificateException
	 * @throws IOException
	 */
	private void loadCERURL(URL url) throws CertificateException, IOException{
		addCertsFromURL("X.509", url);
	}
	
	/**
	 * Method for loading PEM certificate file. Certificates must be bounded at the 
	 * beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by -----END CERTIFICATE-----.
	 * @param certFile
	 * @throws CertificateException
	 * @throws IOException 
	 */
	private void loadPEMFile(File certFile) throws CertificateException, IOException{
		addCertsFromFile("X.509", certFile);
	}
	
	/**
	 * Method for loading PEM certificate file. Certificates must be bounded at the 
	 * beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by -----END CERTIFICATE-----.
	 * @param certFile
	 * @throws CertificateException
	 * @throws IOException 
	 */
	private void loadPEMURL(URL url) throws CertificateException, IOException{
		addCertsFromURL("X.509", url);
	}
	
	/**
	 * method for loading P7B file
	 * @param certFile file containing P7B or P7C bundle
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 */
	private void loadP7BFile(File certFile) throws CertificateException, IOException{
		addCertsFromFile("X.509", certFile);
	}
	
	/**
	 * method for loading P7B file
	 * @param certFile file containing P7B or P7C bundle
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 */
	private void loadP7BURL(URL url) throws CertificateException, IOException{
		addCertsFromURL("X.509", url);
	}
	
	/**
	 * Method for loading PFX file
	 * @param certFile
	 * @throws FileNotFoundException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 */
	private void loadPFXFile(File certFile) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		PasswordPopup passwordPopup = new PasswordPopup();
		Optional<ButtonType> result = passwordPopup.showAndWait();
		if(result.isPresent() && result.get() == ButtonType.OK){
			getPasswordProtectedCerts(passwordPopup.getPassword(), certFile);
		}
		
	}
	
	/**
	 * Method for loading PFX file
	 * @param certFile
	 * @throws FileNotFoundException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 */
	private void loadPFXURL(URL url) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		PasswordPopup passwordPopup = new PasswordPopup();
		Optional<ButtonType> result = passwordPopup.showAndWait();
		if(result.isPresent() && result.get() == ButtonType.OK){
			getPasswordProtectedCerts(passwordPopup.getPassword(), url);
		}
		
	}
	
	/**
	 * Method for removing PKCS7 bounds
	 * @param certFile
	 * @return
	 * @throws IOException
	 */
	public static String removeBoundsP7B(File certFile) throws IOException{
		Scanner reader = new Scanner(new FileReader(certFile));
		StringBuilder cert = new StringBuilder();
		while(reader.hasNext()){
			String line = reader.nextLine();
		    if(!line.contains("PKCS7")){
		    	cert.append(line);
		    }
		}
		
		reader.close();
		
		return cert.toString();
	}

	/**
	 * @return the certs
	 */
	public List<X509Certificate> getCerts() {
		return certs;
	}

	/**
	 * @param certs the certs to set
	 */
	public void setCerts(List<X509Certificate> certs) {
		this.certs = certs;
	}
	
	public List<CertificateBean> getEncapulatedCerts(){
		List<CertificateBean> temp = new ArrayList<>();
		for(X509Certificate cert : certs)
			temp.add(new CertificateBean(cert));
		return temp;
	}
	
//	private void loadCERFile(String certFile) throws CertificateException, IOException{
//		addCertsFromString("X.509", certFile);
//	}
			
	/**
	 * Method for loading base 64 pem string. Certificate/s must be bounded at the 
	 * beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by -----END CERTIFICATE-----.
	 * @param certFile
	 * @throws CertificateException
	 * @throws IOException 
	 */
	private void loadPEMFile(String base64) throws CertificateException, IOException{
		String matchHeader = "-----.*";
		Pattern pattern = Pattern.compile(matchHeader);
		Matcher matcher = pattern.matcher(base64);
		while(matcher.find()){
			int start = matcher.start();
			matcher.find();
			int end = matcher.end();
			addCertFromPEMString(base64.substring(start, end));
		}		
	}
	
//	private void loadP7BFile(String certFile) throws CertificateException, IOException{
//		addCertsFromString("X.509", certFile);
//	}
	
	private void addCertsFromFile(String instanceType, File certFile) throws CertificateException, IOException{
		CertificateFactory factory = CertificateFactory.getInstance(instanceType);
		Collection<? extends Certificate> col = 
				(Collection<? extends Certificate>)factory.generateCertificates(new FileInputStream(certFile));
		Iterator<? extends Certificate> itr = col.iterator();
		while(itr.hasNext()){
			certs.add((X509Certificate)itr.next());
		}
	}
	
	private void getPasswordProtectedCerts(String password, File certFile) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream(certFile), password.toCharArray());
        Enumeration<String> e = p12.aliases();
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            X509Certificate cert = (X509Certificate) p12.getCertificate(alias);
            certs.add(cert);
        }
 
	}
	
	private void getPasswordProtectedCerts(String password, URL url) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(url.openStream(), password.toCharArray());
        Enumeration<String> e = p12.aliases();
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            X509Certificate cert = (X509Certificate) p12.getCertificate(alias);
            certs.add(cert);
        }
 
	}
	
//	private void addCertsFromString(String instanceType, String certFile) throws CertificateException, IOException{
//		CertificateFactory factory = CertificateFactory.getInstance(instanceType);
//		@SuppressWarnings("unchecked")
//		Collection<? extends Certificate> col = 
//				(Collection<? extends Certificate>)factory.generateCertificate(
//						new ByteArrayInputStream(certFile.getBytes()));
//		Iterator<? extends Certificate> itr = col.iterator();
//		while(itr.hasNext()){
//			certs.add((X509Certificate)itr.next());
//		}
//	}
	
	private void addCertFromPEMString(String base64) throws CertificateException{
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = 
				(X509Certificate)factory.generateCertificate(
						new ByteArrayInputStream(base64.getBytes()));
		certs.add(cert);
		
	}
	
	public static List<CertificateBean> encapsulateCertificates(List<X509Certificate> certs){
		List<CertificateBean> beans = new ArrayList<>();
		for(X509Certificate cert : certs){
			beans.add(new CertificateBean(cert));
		}
		
		return beans;
	}
	
	public void addCertsFromDefaultJavaKeyStore(File location, String password) throws Exception{
//		Load the JDK's cacerts keystore file
//		String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
		addCertsFromDefaultJavaKeyStore(new FileInputStream(location), password);
	}
	
	public void addCertsFromDefaultJavaKeyStore(InputStream is, String password) throws Exception{
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	       if(password == null || password.isEmpty()) password = "changeit";
	       keystore.load(is, password.toCharArray());
	       printKeyStore(keystore);
	       // This class retrieves the most-trusted CAs from the keystore
	       PKIXParameters params = new PKIXParameters(keystore);
	       // Get the set of trust anchors, which contain the most-trusted CA certificates
	       Iterator<TrustAnchor> it = params.getTrustAnchors().iterator();
	       
	       while( it.hasNext() ) {
	           TrustAnchor ta = it.next();
	           // Get certificate
	           certs.add(ta.getTrustedCert());
	       }
	}
	
	public void addCertsFromDefaultJavaKeyStore(URL location, String password) throws Exception{
       addCertsFromDefaultJavaKeyStore(location.openStream(), password);
	}
	
	public void printKeyStore(KeyStore ks){
		try {
			Enumeration<String> en = ks.aliases();
			while(en.hasMoreElements()){
				String alias = en.nextElement();
				System.out.println("Alias Name: " + alias);
				System.out.println("Cert: " + ks.getCertificate(alias));
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void addCertsFromDefaultJavaKeyStore(String location, String password) throws Exception{
		addCertsFromDefaultJavaKeyStore(new File(location), password);
	}
	
	private void addCertsFromURL(String instanceType, URL url) throws CertificateException, IOException{
		CertificateFactory factory = CertificateFactory.getInstance(instanceType);
		Collection<? extends Certificate> col = 
				(Collection<? extends Certificate>)factory.generateCertificates(url.openStream());
		Iterator<? extends Certificate> itr = col.iterator();
		while(itr.hasNext()){
			certs.add((X509Certificate)itr.next());
		}
	}
	

}
