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
 * See the License for the specific language governing scopes and
 * limitations under the License.
 */

package com.github.reganjohn.iam.api;

import com.github.adamorgan.jnt.internal.utils.Checks;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.EnumSet;

public enum Scope
{
    APPLICATION_INTERACTION_CREATE(11, "application.interaction.create"),
    APPLICATION_INTERACTION_ACCEPT(12, "application.interaction.accept"),
    UNKNOWN(-1, "unknown");

    /**
     * Empty array of scope enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
     */
    // This is an optimization suggested by Effective Java 3rd Edition - Item 54
    public static final Scope[] EMPTY_SCOPES = new Scope[0];

    private final long offset;
    private final long raw;
    private final String name;

    Scope(long offset, @Nonnull String name)
    {
        this.offset = offset;
        this.raw = 1L << offset;
        this.name = name;
    }

    /**
     * The readable name as used in client.
     *
     * @return The readable name of this {@link com.github.reganjohn.iam.api.Scope Scope}.
     */
    @Nonnull
    public String getName()
    {
        return this.name;
    }

    /**
     * The binary offset of the scope.
     *
     * @return The offset that represents this {@link com.github.reganjohn.iam.api.Scope Scope}.
     */
    public long getOffset()
    {
        return offset;
    }

    /**
     * The value of this scope when viewed as a raw value.
     * <br>This is equivalent to: <code>1 {@literal <<} {@link #getOffset()}</code>
     *
     * @return The raw value of this specific scope.
     */
    public long getRawValue()
    {
        return raw;
    }

    /**
     * Gets the first {@link com.github.reganjohn.iam.api.Scope Scope} relating to the provided offset.
     * <br>If there is no {@link com.github.reganjohn.iam.api.Scope Scope} that matches the provided
     * offset, {@link com.github.reganjohn.iam.api.Scope#UNKNOWN Scope.UNKNOWN} is returned.
     *
     * @param  offset
     *         The offset to match a {@link com.github.reganjohn.iam.api.Scope Scope} to.
     *
     * @return {@link com.github.reganjohn.iam.api.Scope Scope} relating to the provided offset.
     */
    @Nonnull
    public static Scope getFromOffset(int offset)
    {
        for (Scope scope : values())
        {
            if (scope.offset == offset)
            {
                return scope;
            }
        }
        return UNKNOWN;
    }

    /**
     * A set of all {@link com.github.reganjohn.iam.api.Scope Scopes} that are specified by this raw int representation of
     * raw.
     *
     * @param  raw
     *         The raw {@code int} representation of raw.
     *
     * @return Possibly-empty EnumSet of {@link com.github.reganjohn.iam.api.Scope Scopes}.
     */
    @Nonnull
    public static EnumSet<Scope> getScopes(long raw)
    {
        if (raw == 0)
        {
            return EnumSet.noneOf(Scope.class);
        }
        EnumSet<Scope> scopes = EnumSet.noneOf(Scope.class);
        for (Scope scope : Scope.values())
        {
            if (scope != UNKNOWN && (raw & scope.raw) == scope.raw)
            {
                scopes.add(scope);
            }
        }
        return scopes;
    }

    /**
     * This is effectively the opposite of {@link #getScopes(long)}, this takes 1 or more {@link com.github.reganjohn.iam.api.Scope Scopes}
     * and returns the raw offset {@code long} representation of the scopes.
     *
     * @param  scopes
     *         The array of scopes of which to form into the raw long representation.
     *
     * @return Unsigned int representing the provided scopes.
     */
    public static long getRaw(@Nonnull Scope... scopes)
    {
        long raw = 0;
        for (Scope scope : scopes)
        {
            if (scope != null && scope != UNKNOWN)
            {
                raw |= scope.raw;
            }
        }

        return raw;
    }

    /**
     * This is effectively the opposite of {@link #getScopes(long)}, this takes a Collection of {@link com.github.reganjohn.iam.api.Scope Scopes}
     * and returns the raw offset {@code long} representation of the scopes.
     *
     * @param  scopes
     *         The Collection of scopes of which to form into the raw long representation.
     *
     * @return Unsigned long representing the provided scopes.
     *
     * @see    java.util.EnumSet EnumSet
     */
    public static long getRaw(@Nonnull Collection<Scope> scopes)
    {
        Checks.notNull(scopes, "Scope Collection");
        return getRaw(scopes.toArray(EMPTY_SCOPES));
    }
}
