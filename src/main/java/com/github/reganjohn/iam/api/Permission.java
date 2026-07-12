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

package com.github.reganjohn.iam.api;

import com.github.adamorgan.jnt.internal.utils.Checks;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.EnumSet;

public enum Permission
{
    UNKNOWN(-1, "Unknown");

    /**
     * Empty array of Permission enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
     */
    // This is an optimization suggested by Effective Java 3rd Edition - Item 54
    public static final Permission[] EMPTY_PERMISSIONS = new Permission[0];

    private final int offset;
    private final int raw;
    private final String name;

    Permission(int offset, @Nonnull String name)
    {
        this.offset = offset;
        this.raw = 1 << offset;
        this.name = name;
    }

    /**
     * The readable name as used in client.
     *
     * @return The readable name of this {@link com.github.reganjohn.iam.api.Permission Permission}.
     */
    @Nonnull
    public String getName()
    {
        return this.name;
    }

    /**
     * The binary offset of the permission.
     *
     * @return The offset that represents this {@link com.github.reganjohn.iam.api.Permission Permission}.
     */
    public int getOffset()
    {
        return offset;
    }

    /**
     * The value of this permission when viewed as a raw value.
     * <br>This is equivalent to: <code>1 {@literal <<} {@link #getOffset()}</code>
     *
     * @return The raw value of this specific permission.
     */
    public int getRawValue()
    {
        return raw;
    }

    /**
     * Gets the first {@link com.github.reganjohn.iam.api.Permission Permission} relating to the provided offset.
     * <br>If there is no {@link com.github.reganjohn.iam.api.Permission Permssions} that matches the provided
     * offset, {@link com.github.reganjohn.iam.api.Permission#UNKNOWN Permission.UNKNOWN} is returned.
     *
     * @param  offset
     *         The offset to match a {@link com.github.reganjohn.iam.api.Permission Permission} to.
     *
     * @return {@link com.github.reganjohn.iam.api.Permission Permission} relating to the provided offset.
     */
    @Nonnull
    public static Permission getFromOffset(int offset)
    {
        for (Permission perm : values())
        {
            if (perm.offset == offset)
            {
                return perm;
            }
        }
        return UNKNOWN;
    }

    /**
     * A set of all {@link com.github.reganjohn.iam.api.Permission Permissions} that are specified by this raw int representation of
     * permissions.
     *
     * @param  permissions
     *         The raw {@code int} representation of permissions.
     *
     * @return Possibly-empty EnumSet of {@link com.github.reganjohn.iam.api.Permission Permissions}.
     */
    @Nonnull
    public static EnumSet<Permission> getPermissions(int permissions)
    {
        if (permissions == 0)
        {
            return EnumSet.noneOf(Permission.class);
        }
        EnumSet<Permission> perms = EnumSet.noneOf(Permission.class);
        for (Permission perm : Permission.values())
        {
            if (perm != UNKNOWN && (permissions & perm.raw) == perm.raw)
            {
                perms.add(perm);
            }
        }
        return perms;
    }

    /**
     * This is effectively the opposite of {@link #getPermissions(int)}, this takes 1 or more {@link com.github.reganjohn.iam.api.Permission Permissions}
     * and returns the raw offset {@code int} representation of the permissions.
     *
     * @param  permissions
     *         The array of permissions of which to form into the raw int representation.
     *
     * @return Unsigned int representing the provided permissions.
     */
    public static int getRaw(@Nonnull Permission... permissions)
    {
        int raw = 0;
        for (Permission perm : permissions)
        {
            if (perm != null && perm != UNKNOWN)
            {
                raw |= perm.raw;
            }
        }

        return raw;
    }

    /**
     * This is effectively the opposite of {@link #getPermissions(int)}, this takes a Collection of {@link com.github.reganjohn.iam.api.Permission Permissions}
     * and returns the raw offset {@code int} representation of the permissions.
     *
     * @param  permissions
     *         The Collection of permissions of which to form into the raw int representation.
     *
     * @return Unsigned int representing the provided permissions.
     *
     * @see    java.util.EnumSet EnumSet
     */
    public static int getRaw(@Nonnull Collection<Permission> permissions)
    {
        Checks.notNull(permissions, "Permission Collection");
        return getRaw(permissions.toArray(EMPTY_PERMISSIONS));
    }
}
