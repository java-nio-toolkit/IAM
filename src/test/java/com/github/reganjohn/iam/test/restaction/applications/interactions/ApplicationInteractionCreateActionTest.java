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

package com.github.reganjohn.iam.test.restaction.applications.interactions;

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionCreateEvent;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.requests.restactions.applications.interactions.ApplicationInteractionCreateActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ApplicationInteractionCreateActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final String CALLBACK = "https://example.org/callback";
    private static final String VALID = body("permissions", 1, "redirect_uri", CALLBACK);

    private ApplicationInteractionCreateActionImpl newAction()
    {
        return new ApplicationInteractionCreateActionImpl(api);
    }

    private ApplicationInteractionCreateActionImpl newAction(ArgumentCaptor<ApplicationContextInteraction> created)
    {
        ApplicationInteractionCreateActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).createInteraction(created.capture());
        return action;
    }

    private void withStoredApplication(String... redirectUris)
    {
        Application application = withApplication(APPLICATION_ID, OWNER_ID, "app", null, null, "https://example.org", 0, redirectUris);
        User owner = withUser(OWNER_ID, "bob", null, 0);
        withApplication(owner, APPLICATION_ID, completed(application));
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, completed(owner));
    }

    @SuppressWarnings("unchecked")
    private InteractionMappingActionImpl<Void> creation(ApplicationContextInteraction interaction)
    {
        withJCA();
        return (InteractionMappingActionImpl<Void>) newAction().createInteraction(interaction);
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty_body", body()),
                arguments("missing_permissions", body("redirect_uri", CALLBACK)),
                arguments("permissions_not_number", body("permissions", "all", "redirect_uri", CALLBACK)),
                arguments("missing_redirect_uri", body("permissions", 1)),
                arguments("redirect_uri_not_string", body("permissions", 1, "redirect_uri", 5)),
                arguments("redirect_uri_not_url", body("permissions", 1, "redirect_uri", "not-a-url")),
                arguments("everything_invalid", body("permissions", "all", "redirect_uri", 5)));
    }

    static Stream<Arguments> testInvalidApplicationId()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "04d3c48c-1255-7041-8dc9"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
                arguments("without_dashes", "04d3c48c125570418dc9765df2ce977c"));
    }

    static Stream<Arguments> testInvalidOwnerId()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "02b1a26a-f033-7e2f-8ba7"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
                arguments("without_dashes", "02b1a26af0337e2f8ba7543bd0ac755a"));
    }

    @Test
    void testNonObject()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withBody(nonObjectBody())
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withBody(mock(RequestBody.class))
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest(name = "{0}")
    void testInvalidInputs(String name, String json)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidApplicationId(String name, String applicationId)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), applicationId)
                .withJsonBody(VALID)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidOwnerId(String name, String ownerId)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(ownerId, APPLICATION_ID.toString())
                .withJsonBody(VALID)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @ValueSource(strings = {
            "{\"permissions\":0,\"redirect_uri\":\"https://example.org/callback\"}",
            "{\"permissions\":1,\"redirect_uri\":\"https://example.org/callback\"}",
            "{\"permissions\":9223372036854775807,\"redirect_uri\":\"https://example.org/callback\"}",
            "{\"permissions\":1,\"redirect_uri\":\"https://example.org/callback\",\"unknown\":true}"})
    @ParameterizedTest
    void testValidInputs(String json)
    {
        withStoredApplication(CALLBACK);
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatRequestTo(newAction(created))
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withJsonBody(json)
                .hasStatus(StatusReason.CREATED.code)
                .hasNoBody()
                .whenHandled();

        assertThat(created.getAllValues()).hasSize(1);
    }

    @Test
    void testValidInteraction()
    {
        withStoredApplication(CALLBACK, "https://example.org/other");
        List<Object> events = withEventRecorder();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);
        OffsetDateTime before = OffsetDateTime.now();

        assertThatRequestTo(newAction(created))
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withJsonBody(VALID)
                .hasStatus(StatusReason.CREATED.code)
                .checkAssertions(outcome -> assertThat(outcome.response.getHeaders().get("Location"))
                        .containsExactly("users/" + OWNER_ID + "/applications/" + APPLICATION_ID + "/interactions/" + created.getValue().getUniqueId()))
                .whenHandled();

        ApplicationContextInteraction interaction = created.getValue();
        assertThat(interaction.getOwnerId()).isEqualTo(OWNER_ID);
        assertThat(interaction.getApplicationId()).isEqualTo(APPLICATION_ID);
        assertThat(interaction.getUniqueId()).isNotNull();
        assertThat(interaction.getPermissionsRaw()).isEqualTo(1);
        assertThat(interaction.getRedirectUri()).isEqualTo(CALLBACK);
        assertThat(interaction.getTimeExpiresAt()).isBetween(before.plusSeconds(299), OffsetDateTime.now().plusSeconds(301));
        assertThat(events).hasSize(1);
        assertThat(events.get(0)).isInstanceOf(InteractionCreateEvent.class);
        assertThat(((InteractionCreateEvent) events.get(0)).getInteraction()).isSameAs(interaction);
    }

    @ValueSource(strings = {
            "https://example.org/other",
            "https://example.org/callback/",
            "https://example.org/callback?x=1",
            "HTTPS://EXAMPLE.ORG/callback",
            "http://example.org/callback"})
    @ParameterizedTest
    void testUnregisteredRedirectUri(String uri)
    {
        withStoredApplication(CALLBACK);
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatRequestTo(newAction(created))
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withJsonBody(body("permissions", 1, "redirect_uri", uri))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        assertThat(created.getAllValues()).isEmpty();
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withJsonBody(VALID)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownApplication()
    {
        User owner = withUser(OWNER_ID, "bob", null, 0);
        withApplication(owner, APPLICATION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION)));
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, completed(owner));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withJsonBody(VALID)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testCreateFailure()
    {
        withStoredApplication(CALLBACK);
        ApplicationInteractionCreateActionImpl action = spy(newAction());
        doReturn(failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS))).when(action).createInteraction(any());

        assertThatRequestTo(action)
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withJsonBody(VALID)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().createInteraction(null));
    }

    @Test
    void testCreateStatement()
    {
        ApplicationContextInteraction interaction = mock(ApplicationContextInteraction.class);
        when(interaction.getOwnerId()).thenReturn(OWNER_ID);
        when(interaction.getApplicationId()).thenReturn(APPLICATION_ID);
        when(interaction.getUniqueId()).thenReturn(UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d"));
        when(interaction.getPermissionsRaw()).thenReturn(1L);
        when(interaction.getRedirectUri()).thenReturn(CALLBACK);
        when(interaction.getTimeExpiresAt()).thenReturn(OffsetDateTime.parse("2026-01-01T00:05:00Z"));

        InteractionMappingActionImpl<Void> creation = creation(interaction);

        assertThat(creation.getContent()).contains("INSERT INTO integrations.interactions");
        assertThatStatementIsBound(creation);
        assertThat(creation.getParams())
                .containsEntry("user_id", OWNER_ID)
                .containsEntry("application_id", APPLICATION_ID)
                .containsEntry("permissions", 1L)
                .containsEntry("redirect_uri", CALLBACK)
                .containsKeys("interaction_id", "expiry");
    }
}
