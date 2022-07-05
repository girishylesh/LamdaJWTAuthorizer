package com.eauction.aws.lamda.authorizer;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.eauction.aws.exception.JwtTokenMalformedException;
import com.eauction.aws.exception.JwtTokenMissingException;
import com.eauction.aws.lamda.model.AuthorizerResponse;
import com.eauction.aws.lamda.model.PolicyDocument;
import com.eauction.aws.lamda.model.Statement;
import com.eauction.aws.utils.JwtUtil;

public class LamdaAuthorizer implements RequestHandler<APIGatewayProxyRequestEvent, AuthorizerResponse> {

	public AuthorizerResponse handleRequest(APIGatewayProxyRequestEvent request, Context context) {
		Map<String, String> headers = request.getHeaders();
		String token = headers.get("authorization");
		Map<String, String> ctx = new HashMap<>();

		APIGatewayProxyRequestEvent.ProxyRequestContext proxyContext = request.getRequestContext();
		String arn = String.format("arn:aws:execute-api:%s:%s:%s/%s/%s/%s",
				System.getenv("AWS_REGION"),
	            proxyContext.getAccountId(),
	            proxyContext.getApiId(),
	            proxyContext.getStage(),
	            proxyContext.getHttpMethod(),
	            "*");
		
		String effect = "Allow";
		try {
			JwtUtil.validateToken(token);
			ctx.put("message", "Success");
		} catch (JwtTokenMalformedException | JwtTokenMissingException e) {
			effect = "Deny";
			ctx.put("message", e.getMessage());
		}

		Statement statement = Statement.builder().resource(arn).effect(effect).build();

		PolicyDocument policyDocument = PolicyDocument.builder().statements(Collections.singletonList(statement))
				.build();
		return AuthorizerResponse.builder().principalId(proxyContext.getAccountId()).policyDocument(policyDocument)
				.context(ctx).build();
	}
}
