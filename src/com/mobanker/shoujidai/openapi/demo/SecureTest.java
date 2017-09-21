package com.mobanker.shoujidai.openapi.demo;

import java.util.HashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;
import com.mobanker.shoujidai.openapi.demo.common.DES;
import com.mobanker.shoujidai.openapi.demo.common.RSA;

/**
 * �Խ�ǰ¡�ƴ�ͨ��ǩ����ʾ��
 * 1��RSA��������DESKey
 * 2��DES����ҵ��������
 * 3��DES����ҵ��������
 * 4��RSA���ļ�ǩ
 * 5��RSA���Ľ�ǩƥ��
 * 
 * @author chenjianping
 * @data 2017��4��6��
 */
public class SecureTest {

	/*
	 * ˵���� ��openssl���ɵ�˽Կ����Ҫ��pkcs8ת���£�
	 * <pre>
	 * ת������Ϊ��pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt
	 */

	/**
	 * �Խ��̻��Լ��Ĺ�Կ
	 */
	public final static String CLIENT_PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8K7T84gTf0E1dIH1rB1KrzlEC/rtThdD8hzfS+hYzilY6YzQ7/umsXmpYnsxVPqcva0LKod4/rAJbfwFBG+LAGEZoDtm4HFt8CaPIKCt2c81LlJo9r4wtodLTgIpf4AL0A0VT3rA0RJVD7563aiJYdCA9VEYuTqw56cQKsl8PbQIDAQAB";
	/**
	 * �Խ��̻��Լ���˽Կ
	 */
	public final static String CLIENT_PRIVATEKEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALwrtPziBN/QTV0gfWsHUqvOUQL+u1OF0PyHN9L6FjOKVjpjNDv+6axealiezFU+py9rQsqh3j+sAlt/AUEb4sAYRmgO2bgcW3wJo8goK3ZzzUuUmj2vjC2h0tOAil/gAvQDRVPesDRElUPvnrdqIlh0ID1URi5OrDnpxAqyXw9tAgMBAAECgYEAo0tmp+HYiwXwbTWpwTy8oH3NzcSTedrxzoPljQAcTiPpyoeWp84CqOPSdA9ykTNq0HrLnp80CJtT/GTOCNuTPNTjXEaH8SRwGVlYpuSVDBRS+mUF6CWde+ciVIuK3R1Ud1nNEFcvJS+d/H2gInRufefLmdJzMUujgewyHnwaLaECQQDpu8rIXeaOWRPXOwEr+trFb5ceVA/Rh5Yg7T54jyEq9Sm9XMg3mguzKnmLVfXOrVAGpkwhAv8HfArvjiXQOnllAkEAzhi+zRoOpzA3nzDwKDU7gW4CfuyYKX8mU1tGAfdFmjAQa2JMpJmEWYiEM2y8Bez2gJmTAbePs0TPa+l+5JRhaQJAed5jtiNXwmLpuHBYhRDwHr+3YKXd9ZcnjRWGXB/s4FQiJk0JTAxzC0EbTK5OUywErOLqkM/aH5Hqtcs9JhxHDQJAS2eOV6hS+CSSFTJoi61+Sgqf6yRRP81/jjv0zz9TPeib+U4L0KVCYSerhs0fteNPBRorSROKBgMFCOxzOtp3EQJBAMlt3k0K/g+KmVAI3alw020a57EEIXZhzpK87zOgsvMn2rBG2W5yfRWzGX6DVJCQYqlpBwYQiFPxLKBlPnWeqxg=";
	/**
	 * ǰ¡��Կ
	 */
	public final static String QL_PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8K7T84gTf0E1dIH1rB1KrzlEC/rtThdD8hzfS+hYzilY6YzQ7/umsXmpYnsxVPqcva0LKod4/rAJbfwFBG+LAGEZoDtm4HFt8CaPIKCt2c81LlJo9r4wtodLTgIpf4AL0A0VT3rA0RJVD7563aiJYdCA9VEYuTqw56cQKsl8PbQIDAQAB";

	/**
	 * ǰ¡˽Կ(ǰ¡�����ṩ�����Լ�ģ�����ɲ���)
	 */
	public final static String QL_PRIVATEKEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALwrtPziBN/QTV0gfWsHUqvOUQL+u1OF0PyHN9L6FjOKVjpjNDv+6axealiezFU+py9rQsqh3j+sAlt/AUEb4sAYRmgO2bgcW3wJo8goK3ZzzUuUmj2vjC2h0tOAil/gAvQDRVPesDRElUPvnrdqIlh0ID1URi5OrDnpxAqyXw9tAgMBAAECgYEAo0tmp+HYiwXwbTWpwTy8oH3NzcSTedrxzoPljQAcTiPpyoeWp84CqOPSdA9ykTNq0HrLnp80CJtT/GTOCNuTPNTjXEaH8SRwGVlYpuSVDBRS+mUF6CWde+ciVIuK3R1Ud1nNEFcvJS+d/H2gInRufefLmdJzMUujgewyHnwaLaECQQDpu8rIXeaOWRPXOwEr+trFb5ceVA/Rh5Yg7T54jyEq9Sm9XMg3mguzKnmLVfXOrVAGpkwhAv8HfArvjiXQOnllAkEAzhi+zRoOpzA3nzDwKDU7gW4CfuyYKX8mU1tGAfdFmjAQa2JMpJmEWYiEM2y8Bez2gJmTAbePs0TPa+l+5JRhaQJAed5jtiNXwmLpuHBYhRDwHr+3YKXd9ZcnjRWGXB/s4FQiJk0JTAxzC0EbTK5OUywErOLqkM/aH5Hqtcs9JhxHDQJAS2eOV6hS+CSSFTJoi61+Sgqf6yRRP81/jjv0zz9TPeib+U4L0KVCYSerhs0fteNPBRorSROKBgMFCOxzOtp3EQJBAMlt3k0K/g+KmVAI3alw020a57EEIXZhzpK87zOgsvMn2rBG2W5yfRWzGX6DVJCQYqlpBwYQiFPxLKBlPnWeqxg=";
	/**
	 * ��ǰ¡������̻�����
	 */
	public static String merchantId = "201708248210";

	/**
	 * ����DesKey
	 * 
	 * @author chenjianping
	 * @data 2017��4��6��
	 * @Version V1.0
	 * @param str
	 *            ��Ҫ���ܵ����ݣ����ı����ݿ���㶨�壩
	 * @param publicKey
	 *            �ֻ�������Ĺ�Կ
	 * @return
	 */
	public String generateDesKey(String str, String publicKey) {
		return RSA.encryptByPublicKey(str, publicKey);
	}

	/**
	 * ���ļ���
	 * 
	 * @author chenjianping
	 * @data 2017��4��6��
	 * @Version V1.0
	 * @param desKey
	 * @param content
	 *            ��Ҫ���ܵı���
	 * @return
	 */
	public String encode(String desKey, String content) {
		DES crypt = new DES(desKey);
		String cryptStr = "";
		try {
			cryptStr = crypt.encrypt(content);
		} catch (Exception e) {
			System.out.println(e);
		}
		System.out.println("���ܺ���ַ�����" + cryptStr);
		return cryptStr;
	}

	/**
	 * ����ǩ��
	 * 
	 * @author chenjianping
	 * @data 2017��4��6��
	 * @Version V1.0
	 * @param content
	 *            ���ܺ�ı�������
	 * @param privateKey
	 *            ˽Կ
	 * @return
	 */
	public String sign(String content, String privateKey) {
		String sign = RSA.sign(content, privateKey);
		System.out.println("��������ǩ����" + sign);
		return sign;
	}

	/**
	 * ����ǰ¡���ڷ����ļ�ǩ����ʾ��
	 * 
	 * @author chenjianping
	 * @data 2017��4��6��
	 * @Version V1.0
	 */
	public void requestQL(String keyword) {
		Map<String, String> dataMap = new HashMap<String, String>();
		dataMap.put("userPhone", "15300001111");
		String reqData = JSON.toJSONString(dataMap);

		String desKey = generateDesKey(keyword, QL_PUBLICKEY);
		String encodeContent = encode(keyword, reqData);
		String sign = sign(encodeContent, CLIENT_PRIVATEKEY);

		Map<String, String> params = new HashMap<String, String>();
		params.put("merchantId", merchantId);
		params.put("desKey", desKey);
		params.put("sign", sign);
		params.put("reqData", encodeContent);
	}

	/**
	 * ǰ¡���ڷ�����Ӧ���Ľ���ʾ��
	 * 
	 * @author chenjianping
	 * @data 2017��4��6��
	 * @Version V1.0
	 */
	public void responseQL(String keyword) {
		Map<String, String> responseData = simulationQianLongResponse();
		String data = responseData.get("data");
		boolean bool = RSA.verify(data, responseData.get("sign"), QL_PUBLICKEY);
		if (!bool) {
			System.out.println("��ǩʧ�ܣ�");
			return ;
		}
		//desKey���ֺ�����ʱһ��
		DES newDes = new DES(keyword);
		String decryptData = "";
		try {
			decryptData = newDes.decrypt(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("����֮���data����Ϊ��" + decryptData);
	}

	/**
	 * ģ������ǰ¡������Ӧ����
	 * 
	 * @author chenjianping
	 * @data 2017��4��6��
	 * @Version V1.0
	 * @return
	 */
	public Map<String, String> simulationQianLongResponse() {
		Map<String, String> params = new HashMap<String, String>();
		String data = "";// ʹ��des���ܺ�ı��ģ�desKey���ֺ�����ʱ���ɵ�keyһ�£�ע�����Ҫ����base64����
		String sign = "";// ʹ��ǰ¡˽Կ��des���ܺ��data���Ľ���ǩ����ע�����Ҫ����base64����
		params.put("status", "1");
		params.put("error", "00000000");
		params.put("msg", "����ɹ���");
		params.put("sign", sign);
		params.put("data", data);
		return params;
	}

	public static void main(String[] args) throws Exception {
		SecureTest test = new SecureTest();
		String keyword = "qianlong";
		// ����ʾ��
		test.requestQL(keyword);
		// ��Ӧʾ��
		test.responseQL(keyword);
	}

}
