package com.github.reganjohn.iam.api.exceptions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import java.util.List;

public class ErrorResponseException extends InvalidResponseException
{
    public ErrorResponseException(@Nonnull ErrorResponse errorResponse)
    {
        this(errorResponse.getCode(), errorResponse.getMeaning());
    }

    public ErrorResponseException(@Nonnull ErrorResponse errorResponse, @NotNull SchemaError schemaError)
    {
        this(errorResponse.getCode(), errorResponse.getMeaning(), schemaError);
    }

    public ErrorResponseException(@Nonnull ErrorResponse errorResponse, @NotNull List<SchemaError> schemaErrors)
    {
        this(errorResponse.getCode(), errorResponse.getMeaning(), schemaErrors);
    }

    public ErrorResponseException(int code, String meaning)
    {
        super(code, meaning);
    }

    public ErrorResponseException(int code, String meaning, @NotNull SchemaError schemaError)
    {
        super(code, meaning, schemaError);
    }

    public ErrorResponseException(int code, String meaning, @NotNull List<SchemaError> schemaErrors)
    {
        super(code, meaning, schemaErrors);
    }
}
