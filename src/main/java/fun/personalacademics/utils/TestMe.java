package fun.personalacademics.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;

public class TestMe {

	public static void main(String[] args) throws OCSPException {
		// TODO Auto-generated method stub
		try {
			InputStream stream = new FileInputStream("/home/karottop/Desktop/public/Certs/uri_0-ocsp.ocsp");
//			Path path = Paths.get("/home/karottop/Desktop/public/Certs/uri_2-ocsp.ocsp");
//			byte[] data = Files.readAllBytes(path);
//			System.out.println(Arrays.toString(data));
//			ASN1Primitive prim = ASN1Primitive.fromByteArray(data);
//			System.out.println(new BasicOCSPResp(BasicOCSPResponse.getInstance(prim)));
			
//			InputStream reader = stream;
			OCSPResp ocsp = new OCSPResp(stream);
			System.out.println(ocsp.getStatus());
			
			
//			ocsp.toASN1Structure()
//			int resplen = data.length;
//			byte[] ocspResponseEncoded = new byte[data.length];
//
//			int offset = 0;
//			int bread;
//			while ((resplen > 0)
//					&& (bread = reader.read(ocspResponseEncoded, offset, resplen)) != -1) {
//				offset += bread;
//				resplen -= bread;
//			}
//
//			reader.close();
////			con.disconnect();
//			System.out.println(new OCSPResp(ocspResponseEncoded));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
