<?php declare(strict_types=1);
/**
 *                       ######
 *                       ######
 * ############    ####( ######  #####. ######  ############   ############
 * #############  #####( ######  #####. ######  #############  #############
 *        ######  #####( ######  #####. ######  #####  ######  #####  ######
 * ###### ######  #####( ######  #####. ######  #####  #####   #####  ######
 * ###### ######  #####( ######  #####. ######  #####          #####  ######
 * #############  #############  #############  #############  #####  ######
 *  ############   ############  #############   ############  #####  ######
 *                                      ######
 *                               #############
 *                               ############
 *
 * Adyen Webhook Module for PHP
 *
 * Copyright (c) 2021 Adyen N.V.
 * This file is open source and available under the MIT license.
 * See the LICENSE file for more info.
 *
 */

namespace Adyen\Webhook\Receiver;

use Adyen\Webhook\Exception\AuthenticationException;
use Adyen\Webhook\Exception\HMACKeyValidationException;
use Adyen\Webhook\Exception\MerchantAccountCodeException;
use Adyen\Webhook\Exception\InvalidDataException;

class NotificationReceiver
{
    /**
     * @var HmacSignature
     */
    private $hmacSignature;

    /**
     * NotificationReceiver constructor.
     * @param HmacSignature $hmacSignature
     */
    public function __construct(
        HmacSignature $hmacSignature
    ) {
        $this->hmacSignature = $hmacSignature;
    }

    /**
     * Checks if the hmac key is valid
     * @param $response
     * @param $hmacKey
     * @return bool
     * @throws InvalidDataException
     * @throws HMACKeyValidationException
     */
    public function validateHmac($response, $hmacKey)
    {
        $isTestNotification = $this->isTestNotification($response['pspReference'] ?? '');
        if (!$this->hmacSignature->isValidNotificationHMAC($hmacKey, $response)) {
            if ($isTestNotification) {
                $message = 'HMAC key validation failed';
                throw new HMACKeyValidationException($message);
            }
            return false;
        }
        return true;
    }

    /**
     * @param $response
     * @param $merchantAccount
     * @param $notificationUsername
     * @param $notificationPassword
     * @return bool
     * @throws AuthenticationException
     * @throws MerchantAccountCodeException
     */
    public function isAuthenticated($response, $merchantAccount, $notificationUsername, $notificationPassword)
    {
        $submittedMerchantAccount = $response['merchantAccountCode'];

        $isTestNotification = $this->isTestNotification($response['pspReference']);
        if (empty($submittedMerchantAccount) || empty($merchantAccount)) {
            if ($isTestNotification) {
                throw new MerchantAccountCodeException(
                    'merchantAccountCode is empty in settings or in the notification'
                );
            }
            return false;
        }

        $username = $_SERVER['PHP_AUTH_USER'] ?? null;
        $password = $_SERVER['PHP_AUTH_PW'] ?? null;

        if ((!isset($username) || !isset($password)) && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            list($username, $password) = explode(':', base64_decode(substr($_SERVER['HTTP_AUTHORIZATION'], 6)));
        }

        // validate username and password
        if (!isset($username) || !isset($password)) {
            if ($isTestNotification) {
                $message = 'Authentication failed: PHP_AUTH_USER or PHP_AUTH_PW are empty.';
                throw new AuthenticationException($message);
            }
            return false;
        }

        $usernameIsValid = hash_equals($notificationUsername, $username);
        $passwordIsValid = hash_equals($notificationPassword, $password);
        if ($usernameIsValid && $passwordIsValid) {
            return true;
        }

        // If notification is test check if fields are correct if not return error
        if ($isTestNotification) {
            $message = 'username and\or password are not the same as in settings';
            throw new AuthenticationException($message);
        }
        return false;
    }

    /**
     * Checks if notification mode and the store mode configuration matches
     *
     * @param mixed $notificationMode
     * @param bool $testMode
     * @return bool
     */
    public function validateNotificationMode($notificationMode, $testMode)
    {
        // Notification mode can be a string or a boolean
        if (($testMode && ($notificationMode === 'false' || $notificationMode === false)) ||
            (!$testMode && ($notificationMode === 'true' || $notificationMode === true))
        ) {
            return true;
        }
        return false;
    }

    /**
     * If notification is a test notification from Adyen Customer Area
     *
     * @param $pspReference
     * @return bool
     */
    public function isTestNotification($pspReference)
    {
        if (!is_string($pspReference)) {
            return false;
        }

        if (strpos(strtolower($pspReference), 'test_') !== false
            || strpos(strtolower($pspReference), 'testnotification_') !== false
        ) {
            return true;
        }

        return false;
    }

    /**
     * Check if notification is a report notification
     *
     * @param $eventCode
     * @return bool
     */
    public function isReportNotification($eventCode)
    {
        if (strpos($eventCode, 'REPORT_') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Add '[accepted]' into $acceptedMessage if empty
     *
     * @param $acceptedMessage
     * @return string
     */
    public function returnAccepted($acceptedMessage)
    {
        if (empty($acceptedMessage)) {
            $acceptedMessage = '[accepted]';
        }
        return $acceptedMessage;
    }
}
