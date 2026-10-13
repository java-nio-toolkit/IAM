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

package com.github.reganjohn.iam.test.assertions.restaction;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractOverrideActionImpl;
import com.github.reganjohn.iam.test.PrettyRepresentation;
import com.github.reganjohn.iam.test.util.SnapshotHandler;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.CharsetUtil;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.jetbrains.annotations.Contract;
import org.mockito.ThrowingConsumer;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RestActionAssertions implements ThrowingConsumer<RestActionAssertions.Outcome>
{
    private final SnapshotHandler snapshotHandler;

    private final AbstractOverrideActionImpl action;
    private final EmbeddedChannel channel;
    private final ChannelHandlerContext context;
    private final Runnable onHandled;
    private final List<ThrowingConsumer<Outcome>> assertions = new ArrayList<>();
    private final CaseInsensitiveMap<String, Collection<String>> headers = new CaseInsensitiveMap<>();
    private final List<ByteBuf> components = new ArrayList<>();
    private RequestBody body;
    private String[] routeParams = new String[0];

    public RestActionAssertions(SnapshotHandler snapshotHandler, AbstractOverrideActionImpl action,
                                EmbeddedChannel channel, ChannelHandlerContext context, Runnable onHandled)
    {
        this.snapshotHandler = snapshotHandler;
        this.action = action;
        this.channel = channel;
        this.context = context;
        this.onHandled = onHandled;
    }

    @CheckReturnValue
    public static RestActionAssertions assertThatAction(SnapshotHandler snapshotHandler,
                                                        AbstractOverrideActionImpl action,
                                                        EmbeddedChannel channel, ChannelHandlerContext context,
                                                        Runnable onHandled)
    {
        return new RestActionAssertions(snapshotHandler, action, channel, context, onHandled);
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions withJsonBody(@Nonnull String json)
    {
        JacksonRequestBody jackson = mock(JacksonRequestBody.class);
        when(jackson.isObject()).thenReturn(true);
        when(jackson.getObject()).thenReturn(DataObject.fromJson(json));
        this.body = jackson;
        return this;
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions withBody(@Nonnull RequestBody body)
    {
        this.body = body;
        return this;
    }

    @CheckReturnValue
    @Contract("_,_->this")
    public RestActionAssertions withHeader(@Nonnull String name, @Nonnull String value)
    {
        headers.put(name, Collections.singletonList(value));
        return this;
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions withRouteParams(@Nonnull String... params)
    {
        this.routeParams = params;
        return this;
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions checkAssertions(@Nonnull ThrowingConsumer<Outcome> assertion)
    {
        assertions.add(assertion);
        return this;
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasStatus(int code)
    {
        return checkAssertions(outcome ->
        {
            assertThat(outcome.response)
                    .as("RestAction should answer with a response, but failed with %s", outcome.failure)
                    .isNotNull();
            assertThat(outcome.response.code)
                    .as("RestAction should answer with the expected status code")
                    .isEqualTo(code);
        });
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasContentType(@Nonnull MediaType mediaType)
    {
        return checkAssertions(outcome ->
        {
            assertThat(outcome.response).isNotNull();
            assertThat(outcome.response.getBody()).isNotNull();
            assertThat(outcome.response.getBody().contentType())
                    .as("RestAction should answer using the expected content type")
                    .isEqualTo(mediaType);
        });
    }

    @CheckReturnValue
    @Contract("_,_->this")
    public RestActionAssertions hasHeader(@Nonnull String name, @Nonnull String value)
    {
        return checkAssertions(outcome ->
        {
            assertThat(outcome.response).isNotNull();
            assertThat(outcome.response.getHeaders().get(name))
                    .as("RestAction should answer with the expected %s header", name)
                    .containsExactly(value);
        });
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasInteractionResponse(@Nonnull InteractionResponse error, @Nonnull ErrorResponse reason)
    {
        return checkAssertions(outcome ->
        {
            assertThat(outcome.failure).isInstanceOf(InteractionResponseException.class);
            assertThat(((InteractionResponseException) outcome.failure).getError()).isEqualTo(error);
            assertThat(((InteractionResponseException) outcome.failure).getErrorCode()).isEqualTo(reason.getCode());
            assertThat(((InteractionResponseException) outcome.failure).getMeaning()).isEqualTo(reason.getMeaning());
        });
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasJsonBody(@Nonnull ThrowingConsumer<DataObject> assertion)
    {
        return checkAssertions(outcome -> assertion.acceptThrows(DataObject.fromJson(readBody(outcome))));
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasBodyEqualTo(@Nonnull String expected)
    {
        return checkAssertions(outcome -> assertThat(readBody(outcome))
                .as("RestAction should answer using the expected response body")
                .isEqualTo(expected));
    }

    @CheckReturnValue
    @Contract("->this")
    public RestActionAssertions hasBodyMatchingSnapshot()
    {
        return hasBodyMatchingSnapshot(null);
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasBodyMatchingSnapshot(String suffix)
    {
        return checkAssertions(outcome -> snapshotHandler.compareWithSnapshot(readBody(outcome), suffix));
    }

    @CheckReturnValue
    @Contract("->this")
    public RestActionAssertions hasNoBody()
    {
        return checkAssertions(outcome ->
        {
            assertThat(outcome.response)
                    .as("RestAction should answer with a response, but failed with %s", outcome.failure)
                    .isNotNull();
            assertThat(outcome.response.getBody())
                    .as("RestAction should answer without a response body")
                    .isNull();
        });
    }

    @CheckReturnValue
    @Contract("->this")
    public RestActionAssertions hasReleasedBody()
    {
        return checkAssertions(outcome -> ((BufferedResponseBody) outcome.response.getBody()).forEachByte(components::add));
    }

    @CheckReturnValue
    @Contract("->this")
    public RestActionAssertions hasNoResponse()
    {
        return checkAssertions(outcome -> assertThat(outcome.response)
                .as("RestAction should not answer with a response")
                .isNull());
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasFailureOfType(@Nonnull Class<? extends Throwable> type)
    {
        return checkAssertions(outcome -> assertThat(outcome.failure)
                .as("RestAction should fail with the expected exception type")
                .isInstanceOf(type));
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasFailureMatching(@Nonnull Predicate<? super Throwable> condition)
    {
        return checkAssertions(outcome -> assertThat(outcome.failure)
                .withRepresentation(new PrettyRepresentation())
                .matches(condition));
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasFailure(@Nonnull ErrorResponse error)
    {
        return checkAssertions(outcome ->
        {
            assertThat(outcome.failure).isInstanceOf(InvalidResponseException.class);
            assertThat(((InvalidResponseException) outcome.failure).getObject().toMap())
                    .containsOnly(entry("code", error.getCode()), entry("message", error.getMeaning()));
        });
    }

    @CheckReturnValue
    @Contract("_->this")
    @SuppressWarnings("unchecked")
    public RestActionAssertions hasFormErrors(@Nonnull String... pairs)
    {
        Map<String, List<Object>> expected = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2)
            expected.computeIfAbsent(pairs[i], key -> new ArrayList<>()).add(pairs[i + 1]);
        return checkAssertions(outcome ->
        {
            assertThat(outcome.failure).isInstanceOf(InvalidResponseException.class);
            Map<String, Object> object = ((InvalidResponseException) outcome.failure).getObject().toMap();
            assertThat(object).containsEntry("code", ErrorResponse.INVALID_FORM_BODY.getCode())
                    .containsEntry("message", ErrorResponse.INVALID_FORM_BODY.getMeaning());
            Map<String, List<Object>> actual = new LinkedHashMap<>();
            collectFormErrors(null, (Map<String, Object>) object.get("errors"), actual);
            assertThat(actual).isEqualTo(expected);
        });
    }

    @SuppressWarnings("unchecked")
    private static void collectFormErrors(@Nullable String path, @Nonnull Map<String, Object> node, @Nonnull Map<String, List<Object>> errors)
    {
        node.forEach((key, value) ->
        {
            if (key.equals("_errors"))
                ((List<Map<String, Object>>) value).forEach(error -> errors.computeIfAbsent(path, field -> new ArrayList<>()).add(error.get("code")));
            else
                collectFormErrors(path == null ? key : path + "." + key, (Map<String, Object>) value, errors);
        });
    }

    @CheckReturnValue
    @Contract("->this")
    public RestActionAssertions hasFailureMatchingSnapshot()
    {
        return hasFailureMatchingSnapshot(null);
    }

    @CheckReturnValue
    @Contract("_->this")
    public RestActionAssertions hasFailureMatchingSnapshot(String suffix)
    {
        return checkAssertions(outcome ->
        {
            assertThat(outcome.failure).isInstanceOf(InvalidResponseException.class);
            snapshotHandler.compareWithSnapshot(((InvalidResponseException) outcome.failure).getObject(), suffix);
        });
    }

    public void whenHandled()
    {
        Request request = new Request(context, action.getBaseRoute().get(0).compile(routeParams), headers, body);
        Throwable thrown = catchThrowable(() -> action.handleRequest(context, request));
        Throwable piped = catchThrowable(channel::checkException);
        Object outbound = channel.readOutbound();
        onHandled.run();

        Outcome outcome = new Outcome(outbound instanceof Response ? (Response) outbound : null, thrown != null ? thrown : piped);
        try
        {
            acceptThrows(outcome);
        }
        catch (Throwable error)
        {
            throw RestActionAssertions.sneakyThrow(error);
        }
        finally
        {
            release(outcome);
        }
        for (ByteBuf component : components)
            assertThat(component.refCnt()).isZero();
    }

    @Override
    public void acceptThrows(Outcome outcome) throws Throwable
    {
        for (ThrowingConsumer<Outcome> assertion : assertions)
            assertion.acceptThrows(outcome);
    }

    @Nonnull
    private String readBody(@Nonnull Outcome outcome)
    {
        assertThat(outcome.response)
                .as("RestAction should answer with a response, but failed with %s", outcome.failure)
                .isNotNull();
        assertThat(outcome.response.getBody()).isInstanceOf(BufferedResponseBody.class);
        BufferedResponseBody responseBody = (BufferedResponseBody) outcome.response.getBody();
        ByteBuf content = responseBody.next();
        try
        {
            return content.toString(CharsetUtil.UTF_8);
        }
        finally
        {
            content.release();
        }
    }

    private static void release(@Nonnull Outcome outcome)
    {
        if (outcome.response != null && outcome.response.getBody() instanceof BufferedResponseBody)
            ((BufferedResponseBody) outcome.response.getBody()).close();
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> T sneakyThrow(Throwable error) throws T
    {
        throw (T) error;
    }

    public static class Outcome
    {
        public final Response response;
        public final Throwable failure;

        Outcome(@Nullable Response response, @Nullable Throwable failure)
        {
            this.response = response;
            this.failure = failure;
        }
    }
}
