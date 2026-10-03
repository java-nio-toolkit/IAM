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

package com.github.reganjohn.iam.test.restaction.interactions;

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.requests.restactions.interactions.ApplicationInteractionRetrieveActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ApplicationInteractionRetrieveActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final UUID INTERACTION_ID = UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d");
    private static final String CALLBACK = "https://example.org/callback";

    private ApplicationInteractionRetrieveActionImpl newAction()
    {
        return new ApplicationInteractionRetrieveActionImpl(api);
    }

    private static ApplicationContextInteraction newInteraction(OffsetDateTime expiresAt, String label)
    {
        ApplicationContextInteraction interaction = mock(ApplicationContextInteraction.class);
        when(interaction.getOwnerId()).thenReturn(OWNER_ID);
        when(interaction.getApplicationId()).thenReturn(APPLICATION_ID);
        when(interaction.getUniqueId()).thenReturn(INTERACTION_ID);
        when(interaction.getPermissionsRaw()).thenReturn(Permission.VIEW_ACCOUNT.getRawValue());
        when(interaction.getPermissions()).thenReturn(Permission.getPermissions(Permission.VIEW_ACCOUNT.getRawValue()));
        when(interaction.getRedirectUri()).thenReturn(CALLBACK);
        when(interaction.getTimeExpiresAt()).thenReturn(expiresAt);
        when(interaction.getClientNonce()).thenReturn("client-secret-nonce");
        when(interaction.getFinishNonce()).thenReturn("finish-secret-nonce");
        when(interaction.getMethodHash()).thenReturn("sha-256");
        when(interaction.getUri()).thenReturn("https://iam.example/grant");
        when(interaction.hash()).thenReturn("continue-secret-hash");
        when(interaction.getAccessRaw()).thenReturn(DataObject.empty().put("kid", "client-secret-jkt"));
        when(interaction.getLabel()).thenReturn(label);
        return interaction;
    }

    private void withStoredInteraction(ApplicationContextInteraction interaction)
    {
        Application application = withApplication(APPLICATION_ID, OWNER_ID, "app", "description", "icon-cid", "https://example.org", 0, CALLBACK);
        InteractionCallbackAction<ApplicationContextInteraction> retrieval = completed(interaction);
        when(application.retrieveInteractionById(INTERACTION_ID)).thenReturn(retrieval);
        User owner = withUser(OWNER_ID, "bob", null, 0);
        withApplication(owner, APPLICATION_ID, completed(application));
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, completed(owner));
    }

    static Stream<Arguments> testInvalidIds()
    {
        return Stream.of(
                arguments("application_empty", OWNER_ID.toString(), "", INTERACTION_ID.toString()),
                arguments("application_not_uuid", OWNER_ID.toString(), "not-a-uuid", INTERACTION_ID.toString()),
                arguments("interaction_empty", OWNER_ID.toString(), APPLICATION_ID.toString(), ""),
                arguments("interaction_not_uuid", OWNER_ID.toString(), APPLICATION_ID.toString(), "not-a-uuid"),
                arguments("owner_empty", "", APPLICATION_ID.toString(), INTERACTION_ID.toString()),
                arguments("owner_not_uuid", "not-a-uuid", APPLICATION_ID.toString(), INTERACTION_ID.toString()),
                arguments("all_invalid", "not-a-uuid", "not-a-uuid", "not-a-uuid"));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidIds(String name, String ownerId, String applicationId, String interactionId)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(ownerId, applicationId, interactionId)
                .hasFailureOfType(ErrorResponseException.class)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testValidInteraction()
    {
        withStoredInteraction(newInteraction(OffsetDateTime.now().plusSeconds(300), "my-token"));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasContentType(MediaType.parse("application/json; charset=utf-8"))
                .hasJsonBody(json ->
                {
                    assertThat(json.toMap().keySet()).containsExactlyInAnyOrder("interaction_id", "application", "access", "expires_in", "label");
                    assertThat(json.getString("interaction_id")).isEqualTo(INTERACTION_ID.toString());
                    assertThat(json.getString("label")).isEqualTo("my-token");
                    assertThat(json.getLong("expires_in")).isBetween(290L, 300L);
                    assertThat(json.getObject("application").toMap().keySet())
                            .containsExactlyInAnyOrder("application_id", "name", "description", "icon_id", "origin");
                    assertThat(json.getObject("application").getString("application_id")).isEqualTo(APPLICATION_ID.toString());
                    assertThat(json.getObject("application").getString("name")).isEqualTo("app");
                    assertThat(json.getObject("application").getString("description")).isEqualTo("description");
                    assertThat(json.getObject("application").getString("icon_id")).isEqualTo("icon-cid");
                    assertThat(json.getObject("application").getString("origin")).isEqualTo("https://example.org");
                    assertThat(json.getArray("access")).hasSize(1);
                    assertThat(json.getArray("access").getObject(0).getString("type")).isEqualTo("account");
                    assertThat(json.getArray("access").getObject(0).getArray("actions").getString(0)).isEqualTo("read");
                })
                .whenHandled();
    }

    @Test
    void testWithoutLabel()
    {
        withStoredInteraction(newInteraction(OffsetDateTime.now().plusSeconds(300), null));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasJsonBody(json -> assertThat(json.toMap().keySet()).isEqualTo(Set.of("interaction_id", "application", "access", "expires_in")))
                .whenHandled();
    }

    @Test
    void testExpiredInteraction()
    {
        withStoredInteraction(newInteraction(OffsetDateTime.now().minusSeconds(30), null));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasJsonBody(json -> assertThat(json.getLong("expires_in")).isZero())
                .whenHandled();
    }

    @Test
    void testSecretsAreNotExposed()
    {
        withStoredInteraction(newInteraction(OffsetDateTime.now().plusSeconds(300), "my-token"));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasJsonBody(json -> assertThat(json.toString())
                        .doesNotContain("client-secret-nonce", "finish-secret-nonce", "continue-secret-hash", "client-secret-jkt", CALLBACK, "https://iam.example/grant"))
                .whenHandled();
    }

    @Test
    void testUnknownOwner()
    {
        withAccess(USER_ID);
        withRetrieval(OWNER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
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
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .whenHandled();
    }

    @Test
    void testUnknownInteraction()
    {
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
                .whenHandled();
    }

}
