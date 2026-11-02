<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

$finder = (new Finder())
    ->in([__DIR__.'/src', __DIR__.'/tests'])
    // Legacy files not yet formatted: left out until a dedicated style commit.
    ->notPath(['Voter', 'Attribute', 'Traits']);

return (new Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@Symfony' => true,
        '@Symfony:risky' => true,
        'declare_strict_types' => true,
        'global_namespace_import' => ['import_classes' => false, 'import_constants' => false, 'import_functions' => false],
        'native_function_invocation' => ['include' => ['@compiler_optimized'], 'scope' => 'namespaced'],
        'ordered_class_elements' => false,
        'phpdoc_to_comment' => false,
        'php_unit_test_case_static_method_calls' => ['call_type' => 'self'],
    ])
    ->setFinder($finder);
