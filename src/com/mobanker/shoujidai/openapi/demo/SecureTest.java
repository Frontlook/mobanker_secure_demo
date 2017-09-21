package com.mobanker.shoujidai.openapi.demo;

import java.util.HashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;
import com.mobanker.shoujidai.openapi.demo.common.DES;
import com.mobanker.shoujidai.openapi.demo.common.RSA;

/**
 * 对接前隆云贷通加签加密示例
 * 1、RSA加密生成DESKey
 * 2、DES加密业务请求报文
 * 3、DES解密业务请求报文
 * 4、RSA报文加签
 * 5、RSA报文解签匹配
 * 
 * @author chenjianping
 * @data 2017年4月6日
 */
public class SecureTest {

	/*
	 * 说明： 用openssl生成的私钥必须要用pkcs8转换下，
	 * <pre>
	 * 转换命令为：pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt
	 */

	/**
	 * 对接商户自己的公钥
	 */
	public final static String CLIENT_PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8K7T84gTf0E1dIH1rB1KrzlEC/rtThdD8hzfS+hYzilY6YzQ7/umsXmpYnsxVPqcva0LKod4/rAJbfwFBG+LAGEZoDtm4HFt8CaPIKCt2c81LlJo9r4wtodLTgIpf4AL0A0VT3rA0RJVD7563aiJYdCA9VEYuTqw56cQKsl8PbQIDAQAB";
	/**
	 * 对接商户自己的私钥
	 */
	public final static String CLIENT_PRIVATEKEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALwrtPziBN/QTV0gfWsHUqvOUQL+u1OF0PyHN9L6FjOKVjpjNDv+6axealiezFU+py9rQsqh3j+sAlt/AUEb4sAYRmgO2bgcW3wJo8goK3ZzzUuUmj2vjC2h0tOAil/gAvQDRVPesDRElUPvnrdqIlh0ID1URi5OrDnpxAqyXw9tAgMBAAECgYEAo0tmp+HYiwXwbTWpwTy8oH3NzcSTedrxzoPljQAcTiPpyoeWp84CqOPSdA9ykTNq0HrLnp80CJtT/GTOCNuTPNTjXEaH8SRwGVlYpuSVDBRS+mUF6CWde+ciVIuK3R1Ud1nNEFcvJS+d/H2gInRufefLmdJzMUujgewyHnwaLaECQQDpu8rIXeaOWRPXOwEr+trFb5ceVA/Rh5Yg7T54jyEq9Sm9XMg3mguzKnmLVfXOrVAGpkwhAv8HfArvjiXQOnllAkEAzhi+zRoOpzA3nzDwKDU7gW4CfuyYKX8mU1tGAfdFmjAQa2JMpJmEWYiEM2y8Bez2gJmTAbePs0TPa+l+5JRhaQJAed5jtiNXwmLpuHBYhRDwHr+3YKXd9ZcnjRWGXB/s4FQiJk0JTAxzC0EbTK5OUywErOLqkM/aH5Hqtcs9JhxHDQJAS2eOV6hS+CSSFTJoi61+Sgqf6yRRP81/jjv0zz9TPeib+U4L0KVCYSerhs0fteNPBRorSROKBgMFCOxzOtp3EQJBAMlt3k0K/g+KmVAI3alw020a57EEIXZhzpK87zOgsvMn2rBG2W5yfRWzGX6DVJCQYqlpBwYQiFPxLKBlPnWeqxg=";
	/**
	 * 前隆公钥
	 */
	public final static String QL_PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8K7T84gTf0E1dIH1rB1KrzlEC/rtThdD8hzfS+hYzilY6YzQ7/umsXmpYnsxVPqcva0LKod4/rAJbfwFBG+LAGEZoDtm4HFt8CaPIKCt2c81LlJo9r4wtodLTgIpf4AL0A0VT3rA0RJVD7563aiJYdCA9VEYuTqw56cQKsl8PbQIDAQAB";

	/**
	 * 前隆私钥(前隆不会提供，可自己模拟生成测试)
	 */
	public final static String QL_PRIVATEKEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALwrtPziBN/QTV0gfWsHUqvOUQL+u1OF0PyHN9L6FjOKVjpjNDv+6axealiezFU+py9rQsqh3j+sAlt/AUEb4sAYRmgO2bgcW3wJo8goK3ZzzUuUmj2vjC2h0tOAil/gAvQDRVPesDRElUPvnrdqIlh0ID1URi5OrDnpxAqyXw9tAgMBAAECgYEAo0tmp+HYiwXwbTWpwTy8oH3NzcSTedrxzoPljQAcTiPpyoeWp84CqOPSdA9ykTNq0HrLnp80CJtT/GTOCNuTPNTjXEaH8SRwGVlYpuSVDBRS+mUF6CWde+ciVIuK3R1Ud1nNEFcvJS+d/H2gInRufefLmdJzMUujgewyHnwaLaECQQDpu8rIXeaOWRPXOwEr+trFb5ceVA/Rh5Yg7T54jyEq9Sm9XMg3mguzKnmLVfXOrVAGpkwhAv8HfArvjiXQOnllAkEAzhi+zRoOpzA3nzDwKDU7gW4CfuyYKX8mU1tGAfdFmjAQa2JMpJmEWYiEM2y8Bez2gJmTAbePs0TPa+l+5JRhaQJAed5jtiNXwmLpuHBYhRDwHr+3YKXd9ZcnjRWGXB/s4FQiJk0JTAxzC0EbTK5OUywErOLqkM/aH5Hqtcs9JhxHDQJAS2eOV6hS+CSSFTJoi61+Sgqf6yRRP81/jjv0zz9TPeib+U4L0KVCYSerhs0fteNPBRorSROKBgMFCOxzOtp3EQJBAMlt3k0K/g+KmVAI3alw020a57EEIXZhzpK87zOgsvMn2rBG2W5yfRWzGX6DVJCQYqlpBwYQiFPxLKBlPnWeqxg=";
	/**
	 * 有前隆分配的商户编码
	 */
	public static String merchantId = "201708248210";

	/**
	 * 生成DesKey
	 * 
	 * @author chenjianping
	 * @data 2017年4月6日
	 * @Version V1.0
	 * @param str
	 *            需要加密的内容（此文本内容可随便定义）
	 * @param publicKey
	 *            手机贷分配的公钥
	 * @return
	 */
	public String generateDesKey(String str, String publicKey) {
		return RSA.encryptByPublicKey(str, publicKey);
	}

	/**
	 * 报文加密
	 * 
	 * @author chenjianping
	 * @data 2017年4月6日
	 * @Version V1.0
	 * @param desKey
	 * @param content
	 *            需要加密的报文
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
		System.out.println("加密后的字符串：" + cryptStr);
		return cryptStr;
	}

	/**
	 * 报文签名
	 * 
	 * @author chenjianping
	 * @data 2017年4月6日
	 * @Version V1.0
	 * @param content
	 *            加密后的报文内容
	 * @param privateKey
	 *            私钥
	 * @return
	 */
	public String sign(String content, String privateKey) {
		String sign = RSA.sign(content, privateKey);
		System.out.println("报文数据签名：" + sign);
		return sign;
	}

	/**
	 * 请求前隆金融服务报文加签加密示例
	 * 
	 * @author chenjianping
	 * @data 2017年4月6日
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
	 * 前隆金融服务响应报文解析示例
	 * 
	 * @author chenjianping
	 * @data 2017年4月6日
	 * @Version V1.0
	 */
	public void responseQL(String keyword) {
		Map<String, String> responseData = simulationQianLongResponse();
		String data = responseData.get("data");
		boolean bool = RSA.verify(data, responseData.get("sign"), QL_PUBLICKEY);
		if (!bool) {
			System.out.println("验签失败！");
			return ;
		}
		//desKey保持和请求时一致
		DES newDes = new DES(keyword);
		String decryptData = "";
		try {
			decryptData = newDes.decrypt(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("解密之后的data报文为：" + decryptData);
	}

	/**
	 * 模拟生成前隆服务响应报文
	 * 
	 * @author chenjianping
	 * @data 2017年4月6日
	 * @Version V1.0
	 * @return
	 */
	public Map<String, String> simulationQianLongResponse() {
		Map<String, String> params = new HashMap<String, String>();
		String data = "";// 使用des加密后的报文，desKey保持和请求时生成的key一致，注意最后要多用base64编码
		String sign = "";// 使用前隆私钥对des加密后的data报文进行签名，注意最后要多用base64编码
		params.put("status", "1");
		params.put("error", "00000000");
		params.put("msg", "申请成功！");
		params.put("sign", sign);
		params.put("data", data);
		return params;
	}

	public static void main(String[] args) throws Exception {
		SecureTest test = new SecureTest();
		String keyword = "qianlong";
		// 请求示例
		test.requestQL(keyword);
		// 响应示例
		test.responseQL(keyword);
	}

}
