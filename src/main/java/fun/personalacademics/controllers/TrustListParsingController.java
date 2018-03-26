package fun.personalacademics.controllers;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.management.modelmbean.XMLParseException;
import javax.xml.bind.JAXBException;

import com.zeva.temp.jaxb.datamodel.TSPServiceType;
import com.zeva.temp.jaxb.datamodel.TSPType;
import com.zeva.temp.jaxb.datamodel.TrustStatusListType;
import com.zeva.tlgen.utils.xml.JAXBTrustListUnmarshallerV5;
import com.zeva.tlgen.utils.xml.XMLTrustListUnmarshaller;

import biz.ui.filesystem.FriendlyExtensionFilter;
import fun.personalacademics.model.CertificateBean;
import fun.personalacademics.popup.GetURLPopup;
import javafx.scene.control.ButtonType;

@SuppressWarnings("restriction")
public abstract class TrustListParsingController extends CryptToolController{

	@Override
	public abstract void initialize();

	protected TrustStatusListType getEncapsulatedTrustList(File tl) throws JAXBException, XMLParseException{
		XMLTrustListUnmarshaller um = new JAXBTrustListUnmarshallerV5(tl);
		return um.getTrustList();
	}
	
	protected List<TrustStatusListType> getEncapsulatedTrustLists(List<File> files) throws JAXBException, XMLParseException{
		List<TrustStatusListType> tls = new ArrayList<>();
		for(File file : files){
			tls.add(getEncapsulatedTrustList(file));
		}
		return tls;
	}
	
	protected TrustStatusListType getEncapsulatedTrustList(InputStream tl) throws JAXBException, XMLParseException{
		XMLTrustListUnmarshaller um = new JAXBTrustListUnmarshallerV5(tl);
		return um.getTrustList();
	}
		
	protected List<CertificateBean> extractCertsFromTrustList(TrustStatusListType tl){
		List<CertificateBean> beans = new ArrayList<>();
		for(TSPType provider : tl.getTrustServiceProviderList().getTrustServiceProvider()){
			
			for(TSPServiceType service : provider.getServices()){
				for(X509Certificate cert : service.getServiceCerts()){
					beans.add(new CertificateBean(cert));
				}
			}
		}
		return beans;
	}
	
	protected List<CertificateBean> extractCertsFromTrustLists(List<TrustStatusListType> tls){
		List<CertificateBean> beans = new ArrayList<>();
		for(TrustStatusListType tl : tls){
			beans.addAll(extractCertsFromTrustList(tl));
		}

		return beans;
	}
	
	protected List<CertificateBean> getCertsFromTrustList() throws JAXBException, XMLParseException{
		List<File> tls = requestFiles("Import Trust List Certs", 
				null, new FriendlyExtensionFilter("XML File", "*.xml").get());
		return extractCertsFromTrustLists(getEncapsulatedTrustLists(tls));
		
	}
	
	protected List<CertificateBean> getCertsFromTrustListURL() throws MalformedURLException,
												JAXBException, XMLParseException, IOException{
		GetURLPopup url = new GetURLPopup();
		Optional<ButtonType> types = url.showAndWait();
		if(types.isPresent() && types.get() == ButtonType.OK){
			return extractCertsFromTrustList(getEncapsulatedTrustList(url.getURL().openStream()));
		}else{
			return null;
		}
	}
}
