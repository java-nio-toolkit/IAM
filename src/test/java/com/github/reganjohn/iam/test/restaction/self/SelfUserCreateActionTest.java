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

package com.github.reganjohn.iam.test.restaction.self;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.utils.users.UserCreateData;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserCreateActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SelfUserCreateActionTest extends RestActionTest
{
    private static final String VALID_BODY = "{\"username\":\"alice\"}";

    private SelfUserCreateActionImpl newAction()
    {
        return new SelfUserCreateActionImpl(api);
    }

    private SelfUserCreateActionImpl newAction(InteractionCallbackAction<Void> creation, ArgumentCaptor<UserCreateData> created)
    {
        SelfUserCreateActionImpl action = spy(newAction());
        doReturn(creation).when(action).create(created.capture());
        return action;
    }

    @SuppressWarnings("unchecked")
    private static InteractionCallbackAction<Void> succeeding()
    {
        InteractionCallbackAction<Void> creation = mock(InteractionCallbackAction.class);
        doAnswer(invocation -> {
            ((Consumer<Void>) invocation.getArgument(0)).accept(null);
            return null;
        }).when(creation).queue(any(), any());
        return creation;
    }

    @SuppressWarnings("unchecked")
    private static InteractionCallbackAction<Void> failing(Throwable failure)
    {
        InteractionCallbackAction<Void> creation = mock(InteractionCallbackAction.class);
        doAnswer(invocation -> {
            ((Consumer<Throwable>) invocation.getArgument(1)).accept(failure);
            return null;
        }).when(creation).queue(any(), any());
        return creation;
    }

    private static DataObject summarize(UserCreateData user)
    {
        return DataObject.empty()
                .put("username", user.getName())
                .put("avatar_id", user.getAvatarId())
                .put("flags", user.getRawUserFlags())
                .put("session", DataObject.empty()
                        .put("flags", user.getSession().getRawSessionFlags())
                        .put("thumbprint", user.getSession().getThumbprint())
                        .put("user_agent", user.getSession().getUserAgent())
                        .put("belongs_to_user", user.getSession().getUserId().equals(user.getUserId())));
    }

    private static JacksonRequestBody nonObjectBody()
    {
        JacksonRequestBody body = mock(JacksonRequestBody.class);
        when(body.isObject()).thenReturn(false);
        return body;
    }

    private static String body(Object... fields)
    {
        DataObject body = DataObject.empty();
        for (int i = 0; i < fields.length; i += 2)
            body.put((String) fields[i], fields[i + 1]);
        return body.toString();
    }

    private static DataObject session(Object... fields)
    {
        DataObject session = DataObject.empty();
        for (int i = 0; i < fields.length; i += 2)
            session.put((String) fields[i], fields[i + 1]);
        return session;
    }

    static Stream<Arguments> testInvalidInputs()
    {
        String username = StringUtils.repeat('a', User.MAX_NAME_LENGTH + 1);
        String avatar = StringUtils.repeat('a', User.AVATAR_CID_MAX_LENGTH + 1);
        return Stream.of(
                arguments("missing_username", body()),
                arguments("username_not_string", body("username", 5)),
                arguments("username_empty", body("username", "")),
                arguments("username_too_long", body("username", username)),
                arguments("avatar_not_string", body("username", "a", "avatar_id", 5)),
                arguments("avatar_too_long", body("username", "a", "avatar_id", avatar)),
                arguments("flags_not_number", body("username", "a", "flags", "x")),
                arguments("flags_negative", body("username", "a", "flags", -1)),
                arguments("session_flags_not_number", body("username", "a", "session", session("flags", "x"))),
                arguments("session_flags_negative", body("username", "a", "session", session("flags", -1))),
                arguments("every_field_invalid", body("avatar_id", 5, "flags", -1, "session", session("flags", -1))));
    }

    static Stream<String> testValidInputs()
    {
        return Stream.of(
                body("username", "a"),
                body("username", StringUtils.repeat('a', User.MAX_NAME_LENGTH)),
                body("username", "a", "avatar_id", StringUtils.repeat('a', User.AVATAR_CID_MAX_LENGTH)),
                body("username", "a", "avatar_id", ""),
                body("username", "a", "flags", 0),
                body("username", "a", "session", session("flags", 0)),
                body("username", "a", "session", session()));
    }

    static Stream<String> testParsingFailure()
    {
        return Stream.of(
                body("username", null),
                body("username", DataArray.empty()),
                body("username", DataObject.empty()),
                body("username", true),
                body("username", "a", "avatar_id", null),
                body("username", "a", "avatar_id", DataObject.empty()),
                body("username", "a", "avatar_id", DataArray.empty()),
                body("username", "a", "flags", null),
                body("username", "a", "flags", 1.5),
                body("username", "a", "flags", true),
                body("username", "a", "flags", DataArray.empty()),
                body("username", "a", "flags", Long.MAX_VALUE),
                body("username", "a", "session", null),
                body("username", "a", "session", 5),
                body("username", "a", "session", "x"),
                body("username", "a", "session", DataArray.empty()),
                body("username", "a", "session", session("flags", null)),
                body("username", "a", "session", session("flags", 1.5)));
    }

    @Test
    void testNonObject()
    {
        assertThatRequestTo(newAction())
                .withBody(nonObjectBody())
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        assertThatRequestTo(newAction())
                .withBody(mock(RequestBody.class))
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String json)
    {
        assertThatRequestTo(newAction())
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testValidInputs(String json)
    {
        assertThatRequestTo(newAction())
                .withJsonBody(json)
                .hasFailureOfType(ProofAccessException.class)
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testParsingFailure(String json)
    {
        assertThatRequestTo(newAction())
                .withJsonBody(json)
                .hasFailureMatching(failure -> failure instanceof ErrorResponseException || failure instanceof ProofAccessException)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testMissingProof()
    {
        assertThatRequestTo(newAction())
                .withJsonBody(VALID_BODY)
                .hasFailureOfType(ProofAccessException.class)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testValidUser() throws Exception
    {
        withProof();
        ArgumentCaptor<UserCreateData> created = ArgumentCaptor.forClass(UserCreateData.class);

        try (MockedStatic<EntityBuilder> builder = mockStatic(EntityBuilder.class))
        {
            withIssuedObject(builder);

            assertThatRequestTo(newAction(succeeding(), created))
                    .withHeader("User-Agent", "iam-test/1.0")
                    .withJsonBody("{\"username\":\"alice\",\"avatar_id\":\"cid\",\"flags\":1,\"session\":{\"flags\":2}}")
                    .hasStatus(StatusReason.CREATED.code)
                    .hasContentType(SelfUserCreateActionImpl.MEDIA_TYPE_ACCESS)
                    .hasBodyMatchingSnapshot()
                    .whenHandled();
        }

        assertWithSnapshot(summarize(created.getValue()), "user");
        assertThat(created.getValue().getRawUserFlags()).isEqualTo(1L & ~User.UserFlag.SYSTEM);
        assertThat(created.getValue().getSession().getRawSessionFlags()).isEqualTo(2L & ~Session.SessionFlag.SYSTEM);
    }

    @Test
    void testMinimalUser() throws Exception
    {
        withProof();
        ArgumentCaptor<UserCreateData> created = ArgumentCaptor.forClass(UserCreateData.class);

        try (MockedStatic<EntityBuilder> builder = mockStatic(EntityBuilder.class))
        {
            withIssuedObject(builder);

            assertThatRequestTo(newAction(succeeding(), created))
                    .withHeader("User-Agent", "iam-test/1.0")
                    .withJsonBody(VALID_BODY)
                    .hasStatus(StatusReason.CREATED.code)
                    .whenHandled();
        }

        assertWithSnapshot(summarize(created.getValue()), "user");
    }

    @ValueSource(longs = {0, 1, 2, 3, 7, Integer.MAX_VALUE})
    @ParameterizedTest
    void testSystemFlags(long flags) throws Exception
    {
        withProof();
        ArgumentCaptor<UserCreateData> created = ArgumentCaptor.forClass(UserCreateData.class);

        try (MockedStatic<EntityBuilder> builder = mockStatic(EntityBuilder.class))
        {
            withIssuedObject(builder);

            assertThatRequestTo(newAction(succeeding(), created))
                    .withJsonBody("{\"username\":\"alice\",\"flags\":" + flags + ",\"session\":{\"flags\":" + flags + "}}")
                    .hasStatus(StatusReason.CREATED.code)
                    .whenHandled();
        }

        UserCreateData user = created.getValue();
        assertThat(user.getRawUserFlags() & User.UserFlag.SYSTEM).isZero();
        assertThat(user.getRawUserFlags()).isEqualTo(flags & ~User.UserFlag.SYSTEM);
        assertThat(user.getSession().getRawSessionFlags() & Session.SessionFlag.SYSTEM).isZero();
        assertThat(user.getSession().getRawSessionFlags()).isEqualTo(flags & ~Session.SessionFlag.SYSTEM);
    }

    @EnumSource(value = SignType.class, mode = EnumSource.Mode.EXCLUDE, names = {"HS256", "HS384", "HS512", "NONE", "UNKNOWN"})
    @ParameterizedTest
    void testKeyType(SignType type) throws Exception
    {
        AccessEntryData entry = withProof(type);
        ArgumentCaptor<UserCreateData> created = ArgumentCaptor.forClass(UserCreateData.class);

        try (MockedStatic<EntityBuilder> builder = mockStatic(EntityBuilder.class))
        {
            withIssuedObject(builder);

            assertThatRequestTo(newAction(succeeding(), created))
                    .withHeader("User-Agent", "iam-test/1.0")
                    .withJsonBody(VALID_BODY)
                    .hasStatus(StatusReason.CREATED.code)
                    .whenHandled();
        }

        UserCreateData user = created.getValue();
        Map<String, Object> mapping = user.toMap();
        assertThat(user.getSession().getThumbprint()).isEqualTo(entry.getContext(AccessContextType.SHA_256).digest());
        assertThat((byte[]) mapping.get("public_key")).isEqualTo(entry.getPublic().getEncoded());
        assertThat(mapping.get("kid")).isEqualTo(entry.getUniqueId());
        assertWithSnapshot(DataObject.empty()
                .put("kty", mapping.get("kty"))
                .put("alg", mapping.get("alg"))
                .put("usage", mapping.get("usage")), type.name());
    }

    @Test
    void testExistingUser() throws Exception
    {
        withProof();
        ArgumentCaptor<UserCreateData> created = ArgumentCaptor.forClass(UserCreateData.class);
        ErrorResponseException failure = new ErrorResponseException(ErrorResponse.ACCESS_ALREADY_EXISTS);

        try (MockedStatic<EntityBuilder> builder = mockStatic(EntityBuilder.class))
        {
            withIssuedObject(builder);

            assertThatRequestTo(newAction(failing(failure), created))
                    .withJsonBody(VALID_BODY)
                    .hasNoResponse()
                    .hasFailureMatching(error -> error == failure)
                    .hasFailureMatchingSnapshot()
                    .whenHandled();
        }
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().create(null))
                .withMessage("User may not be null");
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCreateApplied() throws Exception
    {
        withJca();
        InteractionMappingActionImpl<Void> creation = (InteractionMappingActionImpl<Void>) newAction().create(mock(UserCreateData.class));
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(true);

        creation.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onSuccess(null);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCreateExisting() throws Exception
    {
        withJca();
        InteractionMappingActionImpl<Void> creation = (InteractionMappingActionImpl<Void>) newAction().create(mock(UserCreateData.class));
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(false);

        creation.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.ACCESS_ALREADY_EXISTS.getCode()));
    }
}
