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

import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionOverrideEvent;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.requests.restactions.applications.interactions.ApplicationInteractionOverrideActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.internal.requests.objaction.InteractionListContextActionImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

public class ApplicationInteractionOverrideActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final UUID INTERACTION_ID = UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d");
    private static final String CALLBACK = "https://example.org/callback";
    private static final String GRANT_URI = "https://iam.example/users/02b1a26a-f033-7e2f-8ba7-543bd0ac755a/applications/04d3c48c-1255-7041-8dc9-765df2ce977c/interactions";

    private AccessEntryData proofEntry;

    private ApplicationInteractionOverrideActionImpl newAction()
    {
        return new ApplicationInteractionOverrideActionImpl(api);
    }

    private void withProofOfUser()
    {
        proofEntry = withProof(SignType.ED25519);
    }

    private static ApplicationContextInteraction newInteraction()
    {
        ApplicationContextInteraction interaction = mock(ApplicationContextInteraction.class);
        when(interaction.getOwnerId()).thenReturn(OWNER_ID);
        when(interaction.getApplicationId()).thenReturn(APPLICATION_ID);
        when(interaction.getUniqueId()).thenReturn(INTERACTION_ID);
        when(interaction.getPermissionsRaw()).thenReturn(1L);
        when(interaction.getRedirectUri()).thenReturn(CALLBACK);
        when(interaction.getTimeExpiresAt()).thenReturn(OffsetDateTime.parse("2026-01-01T00:05:00Z"));
        when(interaction.getClientNonce()).thenReturn("client-nonce");
        when(interaction.getFinishNonce()).thenReturn("finish-nonce");
        when(interaction.getMethodHash()).thenReturn("sha-256");
        when(interaction.getUri()).thenReturn(GRANT_URI);
        when(interaction.hash()).thenReturn("continue-hash");
        when(interaction.getThumbprint()).thenReturn("client-jkt");
        when(interaction.getLabel()).thenReturn("my-token");
        return interaction;
    }

    private void withStoredInteraction(ApplicationContextInteraction interaction)
    {
        Application application = withApplication(APPLICATION_ID, OWNER_ID, "app", null, null, "https://example.org", 0, CALLBACK);
        InteractionCallbackAction<ApplicationContextInteraction> retrieval = completed(interaction);
        when(application.retrieveInteractionById(INTERACTION_ID)).thenReturn(retrieval);
        User owner = withUser(OWNER_ID, "bob", null, 0);
        withApplication(owner, APPLICATION_ID, completed(application));
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, completed(owner));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private MockedConstruction<InteractionListContextActionImpl> mockResponse(List<Object[]> statements)
    {
        return mockConstruction(InteractionListContextActionImpl.class,
                withSettings().defaultAnswer(invocation ->
                {
                    if (invocation.getMethod().getName().equals("add"))
                    {
                        statements.add(invocation.getArguments());
                        return invocation.getMock();
                    }
                    else if (invocation.getMethod().getName().equals("map"))
                        return completed(((Function) invocation.getArgument(0)).apply(null));
                    else
                        return null;
                }),
                (action, context) -> {});
    }

    private static String thumbprintOf(AccessEntryData entry)
    {
        try (AccessContextData contextData = entry.getContext(AccessContextType.SHA_256))
        {
            return contextData.digest();
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
    }

    static Stream<Arguments> testInvalidIds()
    {
        return Stream.of(
                arguments("application_empty", OWNER_ID.toString(), "", INTERACTION_ID.toString()),
                arguments("application_not_uuid", OWNER_ID.toString(), "not-a-uuid", INTERACTION_ID.toString()),
                arguments("application_too_short", OWNER_ID.toString(), "04d3c48c-1255-7041-8dc9", INTERACTION_ID.toString()),
                arguments("interaction_empty", OWNER_ID.toString(), APPLICATION_ID.toString(), ""),
                arguments("interaction_not_uuid", OWNER_ID.toString(), APPLICATION_ID.toString(), "not-a-uuid"),
                arguments("interaction_too_short", OWNER_ID.toString(), APPLICATION_ID.toString(), "05e4d59d-2366-7152-9eda"),
                arguments("owner_empty", "", APPLICATION_ID.toString(), INTERACTION_ID.toString()),
                arguments("owner_not_uuid", "not-a-uuid", APPLICATION_ID.toString(), INTERACTION_ID.toString()),
                arguments("owner_too_short", "02b1a26a-f033-7e2f-8ba7", APPLICATION_ID.toString(), INTERACTION_ID.toString()),
                arguments("all_invalid", "not-a-uuid", "not-a-uuid", "not-a-uuid"));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidIds(String name, String ownerId, String applicationId, String interactionId)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(ownerId, applicationId, interactionId)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testValidInteraction()
    {
        withProofOfUser();
        ApplicationContextInteraction interaction = newInteraction();
        withStoredInteraction(interaction);
        List<Object> events = withEventRecorder();
        ArgumentCaptor<UUID> accepted = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<String> thumbprint = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> reference = ArgumentCaptor.forClass(String.class);
        ApplicationInteractionOverrideActionImpl action = spy(newAction());
        doReturn(completed(interaction)).when(action).createResponse(accepted.capture(), thumbprint.capture(), reference.capture(), any());

        assertThatRequestTo(action)
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasStatus(StatusReason.SEE_OTHER.code)
                .checkAssertions(outcome ->
                {
                    String hash = interactionHashOf("client-nonce", "finish-nonce", reference.getValue(), GRANT_URI);
                    assertThat(outcome.response.getHeaders().get("Location"))
                            .containsExactly(CALLBACK + "?hash=" + hash + "&interact_ref=" + reference.getValue());
                })
                .hasNoBody()
                .whenHandled();

        assertThat(accepted.getValue()).isEqualTo(USER_ID);
        assertThat(thumbprint.getValue()).isEqualTo(thumbprintOf(proofEntry));
        assertThat(reference.getValue()).matches("[A-Za-z0-9_-]{43}");
        assertThat(events).hasSize(1);
        assertThat(events.get(0)).isInstanceOf(InteractionOverrideEvent.class);
        assertThat(((InteractionOverrideEvent) events.get(0)).getInteraction()).isSameAs(interaction);
    }

    @Test
    void testReferenceIsNotReused()
    {
        withProofOfUser();
        ApplicationContextInteraction interaction = newInteraction();
        withStoredInteraction(interaction);
        ArgumentCaptor<String> reference = ArgumentCaptor.forClass(String.class);
        ApplicationInteractionOverrideActionImpl action = spy(newAction());
        doReturn(completed(interaction)).when(action).createResponse(any(), any(), reference.capture(), any());

        for (int i = 0; i < 2; i++)
        {
            assertThatRequestTo(action)
                    .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                    .hasStatus(StatusReason.SEE_OTHER.code)
                    .whenHandled();
        }

        assertThat(reference.getAllValues()).hasSize(2).doesNotHaveDuplicates();
    }

    @Test
    void testMissingProof()
    {
        withStoredInteraction(newInteraction());

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ProofAccessException.class)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testUnknownOwner()
    {
        withProofOfUser();
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownApplication()
    {
        withProofOfUser();
        User owner = withUser(OWNER_ID, "bob", null, 0);
        withApplication(owner, APPLICATION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION)));
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, completed(owner));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownInteraction()
    {
        withProofOfUser();
        Application application = withApplication(APPLICATION_ID, OWNER_ID, "app", null, null, "https://example.org", 0, CALLBACK);
        InteractionCallbackAction<ApplicationContextInteraction> retrieval = failed(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
        when(application.retrieveInteractionById(INTERACTION_ID)).thenReturn(retrieval);
        User owner = withUser(OWNER_ID, "bob", null, 0);
        withApplication(owner, APPLICATION_ID, completed(application));
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, completed(owner));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testResponseFailure()
    {
        withProofOfUser();
        withStoredInteraction(newInteraction());
        ApplicationInteractionOverrideActionImpl action = spy(newAction());
        doReturn(failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS))).when(action).createResponse(any(), any(), any(), any());

        assertThatRequestTo(action)
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSubject(String name, String subject)
    {
        withAccess(subject);

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testCreateResponse()
    {
        withJCA();
        ApplicationContextInteraction interaction = newInteraction();
        List<Object[]> statements = new ArrayList<>();
        ApplicationContextInteraction[] result = new ApplicationContextInteraction[1];

        try (MockedConstruction<InteractionListContextActionImpl> construction = mockResponse(statements))
        {
            InteractionCallbackAction<ApplicationContextInteraction> response = newAction().createResponse(USER_ID, "user-jkt", "reference", interaction);
            response.queue(accepted -> result[0] = accepted, failure -> {});

            assertThat(construction.constructed()).hasSize(1);
        }

        assertThat(result[0]).isSameAs(interaction);
        assertThat(statements).hasSize(3);
        assertThat(statements.get(0)[0].toString()).isEqualTo("DELETE FROM integrations.interactions WHERE user_id = ? AND application_id = ? AND interaction_id = ?");
        assertThat(Arrays.copyOfRange(statements.get(0), 1, 4)).containsExactly(OWNER_ID, APPLICATION_ID, INTERACTION_ID);
        assertThat(statements.get(1)[0].toString()).contains("INSERT INTO integrations.responses");
        assertThat(Arrays.copyOfRange(statements.get(1), 1, 12))
                .containsExactly(INTERACTION_ID, USER_ID, OWNER_ID, APPLICATION_ID, 1L, "reference", "continue-hash", "client-jkt", "user-jkt", "my-token", false);
        assertThat(statements.get(2)[0].toString()).contains("INSERT INTO users.entitlements");
        assertThat(Arrays.copyOfRange(statements.get(2), 1, 6)).containsExactly(USER_ID, APPLICATION_ID, OWNER_ID, 0L, 1L);
        assertThat(statements.get(2)[6]).isInstanceOf(OffsetDateTime.class);
        assertThat(statements.get(1)[0].toString().chars().filter(character -> character == '?').count()).isEqualTo(11);
        assertThat(statements.get(2)[0].toString().chars().filter(character -> character == '?').count()).isEqualTo(6);
    }
}
