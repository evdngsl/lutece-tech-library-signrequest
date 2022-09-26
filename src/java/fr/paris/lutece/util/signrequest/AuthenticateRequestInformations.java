package fr.paris.lutece.util.signrequest;

import java.util.HashMap;
import java.util.Map;

public class AuthenticateRequestInformations {
	
	private Map<String,String> _securityHeaders=new HashMap<String, String>();
	private Map<String,String> _securityParameters=new HashMap<String, String>();
	
	
	public Map<String,String> getSecurityHeaders()
	{
		return _securityHeaders;
	}

	public Map<String,String> getSecurityParameteres()
	{
		return _securityParameters;
	}
	
	
	public  AuthenticateRequestInformations addSecurityParameter(String strParam,String strValue)
	{
		_securityParameters.put(strParam, strValue);
		return  this;
	}
	
	public  AuthenticateRequestInformations  addSecurityHeader(String strParam,String strValue)
	{
		_securityHeaders.put(strParam, strValue);
		return  this;
	}
	
	
	
	
	
}
