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

namespace Adyen\Webhook\Processor;

use Adyen\Webhook\Exception\InvalidDataException;
use Adyen\Webhook\Notification;
use Adyen\Webhook\PaymentStates;
use ReflectionClass;

abstract class Processor implements ProcessorInterface
{

    /**
     * @var Notification
     */
    protected $notification;

    /**
     * @var string
     */
    protected $initialState;

    /**
     * @var bool
     */
    protected $isAutoCapture;

    abstract public function process(): ?string;

    /**
     * @param Notification $notification
     * @param string $state
     * @param bool $isAutoCapture
     * @throws InvalidDataException
     */
    public function __construct(
        Notification $notification,
        string $state,
        bool $isAutoCapture = true
    ) {
        $this->notification = $notification;
        $this->isAutoCapture = $isAutoCapture;
        $this->validateState($state);

        $this->initialState = $state;
    }

    /**
     * @throws InvalidDataException
     */
    protected function validateState($state)
    {
        $paymentStatesClass = new ReflectionClass(PaymentStates::class);
        if (!in_array($state, $paymentStatesClass->getConstants())) {
            throw new InvalidDataException('Invalid state.');
        }
    }

    /**
     * In case of unchanged payment state based on notification log
     * the eventCode, originalState and newState
     * @return string
     */
    protected function unchanged(): string
    {
        return $this->initialState;
    }
}
