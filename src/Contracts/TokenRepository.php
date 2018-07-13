<?php

namespace Yaquawa\Laravel\TokenRepository\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface TokenRepository
{
    /**
     * Create a new token.
     *
     * @param Authenticatable $user
     *
     * @return string
     */
    public function create(Authenticatable $user);

    /**
     * Get the record by the given user's id
     * and make sure the token is not expired.
     *
     * @param Authenticatable $user
     * @param string $token
     *
     * @return array|null
     */
    public function find(Authenticatable $user, string $token);

    /**
     * Determine if a token record exists and is valid.
     *
     * @param Authenticatable $user
     * @param  string $token
     *
     * @return bool
     */
    public function exists(Authenticatable $user, $token);

    /**
     * Delete a token record.
     *
     * @param Authenticatable $user
     *
     * @return void
     */
    public function delete(Authenticatable $user);

    /**
     * Delete expired tokens.
     *
     * @return void
     */
    public function deleteExpired();
}
