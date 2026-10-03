/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.test.managers;

import com.fasterxml.jackson.core.JsonParseException;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.internal.managers.ErrorObjectManagerImpl;
import com.github.reganjohn.iam.test.IntegrationTest;
import io.netty.util.CharsetUtil;
import java.io.IOException;
import java.security.DigestException;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class ErrorObjectManagerTest extends IntegrationTest
{
    private Response handle(Throwable error)
    {
        try
        {
            new ErrorObjectManagerImpl(false).exceptionCaught(context, error);
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
        Object outbound = channel.readOutbound();
        assertThat(outbound).isInstanceOf(Response.class);
        return (Response) outbound;
    }

    private static String read(Response response)
    {
        BufferedResponseBody body = (BufferedResponseBody) response.getBody();
        try
        {
            return body.next().toString(CharsetUtil.UTF_8);
        }
        finally
        {
            body.close();
        }
    }

    static Stream<Arguments> testStatus()
    {
        return Stream.of(
                arguments(InteractionResponse.INVALID_REQUEST, 400),
                arguments(InteractionResponse.INVALID_FLAG, 400),
                arguments(InteractionResponse.INVALID_CLIENT, 401),
                arguments(InteractionResponse.INVALID_CONTINUATION, 401),
                arguments(InteractionResponse.UNKNOWN_INTERACTION, 404),
                arguments(InteractionResponse.TOO_MANY_ATTEMPTS, 429),
                arguments(InteractionResponse.INVALID_INTERACTION, 403),
                arguments(InteractionResponse.USER_DENIED, 403),
                arguments(InteractionResponse.REQUEST_DENIED, 403));
    }

    @MethodSource
    @ParameterizedTest
    void testStatus(InteractionResponse error, int status)
    {
        assertThat(handle(new InteractionResponseException(error, ErrorResponse.MISSING_ACCESS)).code).isEqualTo(status);
    }

    @Test
    void testUnknownFailure()
    {
        Response response = handle(new NullPointerException("secret detail"));

        assertThat(response.code).isEqualTo(500);
        assertThat(read(response)).contains(ErrorResponse.SERVER_ERROR.getMeaning()).doesNotContain("secret detail");
    }

    @Test
    void testInputOutputFailure()
    {
        Response response = handle(new IOException("secret detail"));

        assertThat(response.code).isEqualTo(500);
        assertThat(read(response)).contains(ErrorResponse.SERVER_ERROR.getMeaning()).doesNotContain("secret detail");
    }

    @Test
    void testWrappedJsonFailure()
    {
        Response response = handle(new IllegalStateException(new JsonParseException(null, "Unrecognized token")));

        assertThat(response.code).isEqualTo(400);
        assertThat(read(response)).contains(ErrorResponse.INVALID_REQUEST_BODY.getMeaning());
    }

    @Test
    void testJsonFailure()
    {
        Response response = handle(new JsonParseException(null, "Unrecognized token"));

        assertThat(response.code).isEqualTo(400);
        assertThat(read(response)).contains(ErrorResponse.INVALID_REQUEST_BODY.getMeaning());
    }

    @Test
    void testStackTraceFlag() throws Exception
    {
        new ErrorObjectManagerImpl(true).exceptionCaught(context, new IllegalStateException("x"));

        assertThat((Object) channel.readOutbound()).isNotNull();
    }

    @Test
    void testUnsupportedDigestMode()
    {
        Response response = handle(new UnsupportedOperationException("The used digest mode is not supported."));

        assertThat(response.code).isEqualTo(400);
        assertThat(read(response)).contains("The used digest mode is not supported.");
    }

    @Test
    void testDigestMismatch()
    {
        Response response = handle(new DigestException("Content-Digest did not match the expected."));

        assertThat(response.code).isEqualTo(400);
        assertThat(read(response)).contains("Content-Digest did not match the expected.");
    }

    @Test
    void testKeySpecFailure()
    {
        Response response = handle(new InvalidKeySpecException("Unsupported access type: ES256"));

        assertThat(response.code).isEqualTo(400);
        assertThat(read(response)).contains("Unsupported access type: ES256");
    }

    @Test
    void testStatusOfEveryResponse()
    {
        assertThat(testStatus().map(arguments -> arguments.get()[0])).containsExactlyInAnyOrder((Object[]) InteractionResponse.values());
    }

    @EnumSource(InteractionResponse.class)
    @ParameterizedTest
    void testInteractionResponse(InteractionResponse error)
    {
        Response response = handle(new InteractionResponseException(error, ErrorResponse.UNKNOWN_TOKEN));

        assertThat(response.getBody().contentType()).isEqualTo(MediaType.parse("application/json; charset=utf-8"));
        DataObject json = DataObject.fromJson(read(response));
        assertThat(json.toMap().keySet()).containsExactly("error");
        assertThat(json.getObject("error").toMap().keySet()).containsExactly("code", "error");
        assertThat(json.getObject("error").getInt("code")).isEqualTo(ErrorResponse.UNKNOWN_TOKEN.getCode());
        assertThat(json.getObject("error").getObject("error").toMap().keySet()).containsExactly("code", "meaning");
        assertThat(json.getObject("error").getObject("error").getString("code")).isEqualTo(error.getCode());
        assertThat(json.getObject("error").getObject("error").getString("meaning")).isEqualTo("Unknown Token");
    }

    @Test
    void testInteractionResponseCodes()
    {
        assertThat(InteractionResponse.values()).extracting(InteractionResponse::getCode).containsExactlyInAnyOrder(
                "invalid_request", "invalid_client", "invalid_interaction", "invalid_flag", "invalid_continuation",
                "user_denied", "request_denied", "unknown_interaction", "too_many_attempts");
    }

    @Test
    void testInteractionResponseReason()
    {
        InteractionResponseException exception = new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.UNKNOWN_ACCESS);

        assertThat(exception).isInstanceOf(ErrorResponseException.class);
        assertThat(exception.getError()).isEqualTo(InteractionResponse.INVALID_CLIENT);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorResponse.UNKNOWN_ACCESS.getCode());
        assertThat(exception.getMeaning()).isEqualTo("Unknown Access");
    }
}
