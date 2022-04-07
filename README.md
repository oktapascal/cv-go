
# CV-GO

Rest API untuk CV-VUE project pribadi untuk mengolah data project yang pernah dikerjakan


## Installation

```bash
  go install
```
    
## Refensi API

#### Get Authorization
```http
  POST /login
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `access-token` | `cookie` | **Required**. Your API key |

#### Get user data

```http
  GET /user
```

#### Get user avatar

```http
  GET /user-image
```

#### Update user data

```http
  POST /user
```

#### Upload avatar user

```http
  POST /user-upload
```

#### Get data projects

```http
  GET /projects
```

#### Get one data projects

```http
  GET /project?id=
```

#### Save data project

```http
  POST /project-simpan
```

#### Update data project

```http
  POST /project-update
```


## Authors

- [@oktapascal](https://www.github.com/oktapascal)

